/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 John Ericson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Tests for proc_new(), proc_setfd(), and proc_start() syscalls.
 */

#include <sys/types.h>
#include <sys/procdesc.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

/*
 * Helper: open an executable by path and return the fd.
 */
static int
open_exec(const char *path)
{
	int fd;

	fd = open(path, O_RDONLY | O_EXEC);
	ATF_REQUIRE_MSG(fd >= 0, "open(%s): %s", path, strerror(errno));
	return (fd);
}

/*
 * Basic lifecycle: proc_new + proc_start + pdwait.
 * Run /bin/true and verify exit status 0.
 */
ATF_TC_WITHOUT_HEAD(basic_true);
ATF_TC_BODY(basic_true, tc)
{
	char *argv[] = { __DECONST(char *, "true"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd, status;

	execfd = open_exec("/bin/true");

	error = proc_new(execfd, argv, envv, &procfd, 0);
	ATF_REQUIRE_MSG(error == 0,
	    "proc_new: %s", strerror(errno));
	close(execfd);

	error = proc_start(procfd);
	ATF_REQUIRE_MSG(error == 0,
	    "proc_start: %s", strerror(errno));

	error = pdwait(procfd, &status, 0, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0,
	    "pdwait: %s", strerror(errno));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "unexpected exit status: %#x", status);

	close(procfd);
}

/*
 * Run /usr/bin/false and verify exit status 1.
 */
ATF_TC_WITHOUT_HEAD(basic_false);
ATF_TC_BODY(basic_false, tc)
{
	char *argv[] = { __DECONST(char *, "false"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd, status;

	execfd = open_exec("/usr/bin/false");

	error = proc_new(execfd, argv, envv, &procfd, 0);
	ATF_REQUIRE_MSG(error == 0,
	    "proc_new: %s", strerror(errno));
	close(execfd);

	error = proc_start(procfd);
	ATF_REQUIRE_MSG(error == 0,
	    "proc_start: %s", strerror(errno));

	error = pdwait(procfd, &status, 0, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0,
	    "pdwait: %s", strerror(errno));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 1,
	    "unexpected exit status: %#x", status);

	close(procfd);
}

/*
 * Set up stdout via proc_setfd and verify output.
 * Run /bin/echo with a pipe on stdout, read from the pipe.
 */
ATF_TC_WITHOUT_HEAD(setfd_stdout);
ATF_TC_BODY(setfd_stdout, tc)
{
	char buf[128];
	char *argv[] = { __DECONST(char *, "echo"),
	    __DECONST(char *, "hello"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd, status;
	int pipefd[2];
	ssize_t n;

	ATF_REQUIRE(pipe(pipefd) == 0);
	execfd = open_exec("/bin/echo");

	error = proc_new(execfd, argv, envv, &procfd, 0);
	ATF_REQUIRE_MSG(error == 0,
	    "proc_new: %s", strerror(errno));
	close(execfd);

	/* Install the write end of the pipe as the child's stdout. */
	error = proc_setfd(procfd, STDOUT_FILENO, pipefd[1]);
	ATF_REQUIRE_MSG(error == 0,
	    "proc_setfd: %s", strerror(errno));
	close(pipefd[1]);

	error = proc_start(procfd);
	ATF_REQUIRE_MSG(error == 0,
	    "proc_start: %s", strerror(errno));

	/* Read from the pipe. */
	n = read(pipefd[0], buf, sizeof(buf) - 1);
	ATF_REQUIRE_MSG(n > 0, "read: %s", strerror(errno));
	buf[n] = '\0';
	ATF_REQUIRE_MSG(strcmp(buf, "hello\n") == 0,
	    "unexpected output: '%s'", buf);
	close(pipefd[0]);

	error = pdwait(procfd, &status, 0, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0,
	    "pdwait: %s", strerror(errno));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	close(procfd);
}

/*
 * Set up stdin via proc_setfd.
 * Pipe data to /usr/bin/cat, read from its stdout.
 */
ATF_TC_WITHOUT_HEAD(setfd_stdin);
ATF_TC_BODY(setfd_stdin, tc)
{
	char buf[128];
	char *argv[] = { __DECONST(char *, "cat"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd, status;
	int in_pipe[2], out_pipe[2];
	ssize_t n;

	ATF_REQUIRE(pipe(in_pipe) == 0);
	ATF_REQUIRE(pipe(out_pipe) == 0);
	execfd = open_exec("/bin/cat");

	error = proc_new(execfd, argv, envv, &procfd, 0);
	ATF_REQUIRE_MSG(error == 0,
	    "proc_new: %s", strerror(errno));
	close(execfd);

	error = proc_setfd(procfd, STDIN_FILENO, in_pipe[0]);
	ATF_REQUIRE_MSG(error == 0, "proc_setfd stdin: %s", strerror(errno));
	close(in_pipe[0]);

	error = proc_setfd(procfd, STDOUT_FILENO, out_pipe[1]);
	ATF_REQUIRE_MSG(error == 0, "proc_setfd stdout: %s", strerror(errno));
	close(out_pipe[1]);

	error = proc_start(procfd);
	ATF_REQUIRE_MSG(error == 0, "proc_start: %s", strerror(errno));

	/* Write to cat's stdin, then close to signal EOF. */
	ATF_REQUIRE(write(in_pipe[1], "world\n", 6) == 6);
	close(in_pipe[1]);

	/* Read cat's stdout. */
	n = read(out_pipe[0], buf, sizeof(buf) - 1);
	ATF_REQUIRE_MSG(n > 0, "read: %s", strerror(errno));
	buf[n] = '\0';
	ATF_REQUIRE_MSG(strcmp(buf, "world\n") == 0,
	    "unexpected output: '%s'", buf);
	close(out_pipe[0]);

	error = pdwait(procfd, &status, 0, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	close(procfd);
}

/*
 * Error: proc_new with a non-executable file.
 */
ATF_TC_WITHOUT_HEAD(error_noexec);
ATF_TC_BODY(error_noexec, tc)
{
	char *argv[] = { __DECONST(char *, "null"), NULL };
	char *envv[] = { NULL };
	int error, fd, procfd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	error = proc_new(fd, argv, envv, &procfd, 0);
	ATF_REQUIRE_MSG(error == -1, "proc_new should have failed");
	ATF_REQUIRE_MSG(errno == ENOEXEC || errno == EACCES,
	    "unexpected errno: %d (%s)", errno, strerror(errno));

	close(fd);
}

/*
 * Error: proc_start with an invalid fd.
 */
ATF_TC_WITHOUT_HEAD(error_bad_procfd);
ATF_TC_BODY(error_bad_procfd, tc)
{
	int error;

	error = proc_start(999);
	ATF_REQUIRE_MSG(error == -1, "proc_start should have failed");
	ATF_REQUIRE_MSG(errno == EBADF,
	    "unexpected errno: %d (%s)", errno, strerror(errno));
}

/*
 * Cleanup: close procfd before proc_start, ensure no zombie/leak.
 */
ATF_TC_WITHOUT_HEAD(close_before_start);
ATF_TC_BODY(close_before_start, tc)
{
	char *argv[] = { __DECONST(char *, "true"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd;

	execfd = open_exec("/bin/true");

	error = proc_new(execfd, argv, envv, &procfd, 0);
	ATF_REQUIRE_MSG(error == 0,
	    "proc_new: %s", strerror(errno));
	close(execfd);

	/*
	 * Close the procfd without starting.  The embryonic process
	 * should be destroyed (no zombie, no resource leak).
	 */
	close(procfd);

	/* If we get here without hanging, the test passes. */
}

/*
 * proc_setfd: replace an already-set fd.
 */
ATF_TC_WITHOUT_HEAD(setfd_replace);
ATF_TC_BODY(setfd_replace, tc)
{
	char buf[128];
	char *argv[] = { __DECONST(char *, "echo"),
	    __DECONST(char *, "replaced"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd, status;
	int pipe1[2], pipe2[2];
	ssize_t n;

	ATF_REQUIRE(pipe(pipe1) == 0);
	ATF_REQUIRE(pipe(pipe2) == 0);
	execfd = open_exec("/bin/echo");

	error = proc_new(execfd, argv, envv, &procfd, 0);
	ATF_REQUIRE_MSG(error == 0, "proc_new: %s", strerror(errno));
	close(execfd);

	/* Set stdout to pipe1, then replace with pipe2. */
	error = proc_setfd(procfd, STDOUT_FILENO, pipe1[1]);
	ATF_REQUIRE_MSG(error == 0, "proc_setfd 1: %s", strerror(errno));

	error = proc_setfd(procfd, STDOUT_FILENO, pipe2[1]);
	ATF_REQUIRE_MSG(error == 0, "proc_setfd 2: %s", strerror(errno));
	close(pipe1[1]);
	close(pipe2[1]);

	error = proc_start(procfd);
	ATF_REQUIRE_MSG(error == 0, "proc_start: %s", strerror(errno));

	/* pipe1 should get nothing (was replaced). */
	n = read(pipe1[0], buf, sizeof(buf));
	ATF_REQUIRE_MSG(n == 0, "pipe1 should be empty, got %zd bytes", n);
	close(pipe1[0]);

	/* pipe2 should get the output. */
	n = read(pipe2[0], buf, sizeof(buf) - 1);
	ATF_REQUIRE_MSG(n > 0, "read pipe2: %s", strerror(errno));
	buf[n] = '\0';
	ATF_REQUIRE_MSG(strcmp(buf, "replaced\n") == 0,
	    "unexpected output: '%s'", buf);
	close(pipe2[0]);

	error = pdwait(procfd, &status, 0, NULL, NULL);
	ATF_REQUIRE(error == 0);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	close(procfd);
}

/*
 * Shebang: exec a shell script via proc_new.
 * Create a temporary script, exec it, verify output.
 */
ATF_TC_WITHOUT_HEAD(shebang);
ATF_TC_BODY(shebang, tc)
{
	char buf[128];
	char *argv[] = { __DECONST(char *, "testscript"), NULL };
	char *envv[] = { NULL };
	char scriptpath[] = "/tmp/proc_new_test.XXXXXX";
	int error, execfd, procfd, scriptfd, status;
	int pipefd[2];
	ssize_t n;

	/* Create a temporary shell script. */
	scriptfd = mkstemp(scriptpath);
	ATF_REQUIRE_MSG(scriptfd >= 0, "mkstemp: %s", strerror(errno));
	ATF_REQUIRE(write(scriptfd, "#!/bin/sh\necho shebang\n", 23) == 23);
	ATF_REQUIRE(fchmod(scriptfd, 0755) == 0);
	close(scriptfd);

	ATF_REQUIRE(pipe(pipefd) == 0);
	execfd = open_exec(scriptpath);

	error = proc_new(execfd, argv, envv, &procfd, 0);
	ATF_REQUIRE_MSG(error == 0, "proc_new: %s", strerror(errno));
	close(execfd);

	error = proc_setfd(procfd, STDOUT_FILENO, pipefd[1]);
	ATF_REQUIRE_MSG(error == 0, "proc_setfd: %s", strerror(errno));
	close(pipefd[1]);

	error = proc_start(procfd);
	ATF_REQUIRE_MSG(error == 0, "proc_start: %s", strerror(errno));

	n = read(pipefd[0], buf, sizeof(buf) - 1);
	ATF_REQUIRE_MSG(n > 0, "read: %s", strerror(errno));
	buf[n] = '\0';
	ATF_REQUIRE_MSG(strcmp(buf, "shebang\n") == 0,
	    "unexpected output: '%s'", buf);
	close(pipefd[0]);

	error = pdwait(procfd, &status, 0, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	close(procfd);
	unlink(scriptpath);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, basic_true);
	ATF_TP_ADD_TC(tp, basic_false);
	ATF_TP_ADD_TC(tp, setfd_stdout);
	ATF_TP_ADD_TC(tp, setfd_stdin);
	ATF_TP_ADD_TC(tp, error_noexec);
	ATF_TP_ADD_TC(tp, error_bad_procfd);
	ATF_TP_ADD_TC(tp, close_before_start);
	ATF_TP_ADD_TC(tp, setfd_replace);
	ATF_TP_ADD_TC(tp, shebang);

	return (atf_no_error());
}
