// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <pthread.h>
#include <unistd.h>
#include <stdatomic.h>
#include <bpf/libbpf.h>
#include "bootstrap.h"
#include "bootstrap.skel.h"

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

/* Minimal structures to access ring buffer internals */
struct ring {
	void *sample_cb;
	void *ctx;
	void *data;
	unsigned long *consumer_pos;
	/* ... other fields we don't need */
};

struct ring_buffer_internal {
	void *events;
	struct ring **rings;
	/* ... other fields we don't need */
};

/* Shared variables between threads */
static volatile const struct event *shared_event_ptr = NULL;
static pthread_t printer_thread;

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] = "BPF bootstrap demo application.\n"
				"\n"
				"It traces process start and exits and shows associated \n"
				"information (filename, process duration, PID and PPID, etc).\n"
				"\n"
				"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static void *printer_thread_func(void *arg)
{
	const struct event *e;
	struct tm *tm;
	char ts[32];
	time_t t;
	unsigned long *consumer_pos = (unsigned long *)arg;
	unsigned long last_consumer_pos = 0;
	unsigned long current_consumer_pos;

	if (!consumer_pos) {
		fprintf(stderr, "Invalid consumer_pos pointer\n");
		return NULL;
	}

	while (!exiting) {
		/* Check if consumer_pos has changed */
		current_consumer_pos = atomic_load_explicit((_Atomic unsigned long *)consumer_pos, memory_order_acquire);
		if (current_consumer_pos != last_consumer_pos) {
			last_consumer_pos = current_consumer_pos;
			
			/* Load the shared event and print */
			e = (const struct event *)shared_event_ptr;
			if (e) {
				/* Process and print the event */
				time(&t);
				tm = localtime(&t);
				strftime(ts, sizeof(ts), "%H:%M:%S", tm);

				if (e->exit_event) {
					printf("%-8s %-5s %-16s %-7d %-7d [%u] @%p", ts, "EXIT", e->comm, e->pid, e->ppid,
					       e->exit_code, (void*)e);
					if (e->duration_ns)
						printf(" (%llums)", e->duration_ns / 1000000);
					printf("\n");
				} else {
					printf("%-8s %-5s %-16s %-7d %-7d %s @%p\n", ts, "EXEC", e->comm, e->pid, e->ppid,
					       e->filename, (void*)e);
				}
			}
		} else {
			/* Small delay to avoid busy waiting */
			usleep(1000); /* 1ms */
		}
	}
	return NULL;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	/* Update shared event pointer for printer thread */
	shared_event_ptr = e;

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct bootstrap_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = bootstrap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	/* Load & verify BPF programs */
	err = bootstrap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = bootstrap_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Extract consumer_pos from the first ring to pass to printer thread */
	struct ring_buffer_internal *rb_internal = (struct ring_buffer_internal *)rb;
	unsigned long *consumer_pos = rb_internal->rings[0]->consumer_pos;

	/* Start printer thread with consumer_pos */
	err = pthread_create(&printer_thread, NULL, printer_thread_func, consumer_pos);
	if (err) {
		fprintf(stderr, "Failed to create printer thread: %d\n", err);
		goto cleanup;
	}

	/* Process events */
	printf("%-8s %-5s %-16s %-7s %-7s %-18s %s\n", "TIME", "EVENT", "COMM", "PID", "PPID",
	       "FILENAME/EXIT CODE", "EVENT_ADDR");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

	/* Wait for printer thread to finish */
	pthread_join(printer_thread, NULL);

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	bootstrap_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
