/*
 * main.c — BioAuth daemon entry point
 *
 * Copyright (C) 2024 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "daemon/bio_daemon.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{

    int filtered_argc = 0;
    int rc;
    char **filtered_argv = NULL;

    filtered_argv = calloc((size_t)argc + 1u, sizeof(char *));
    if (!filtered_argv)
    {
        return 1;
    }

    filtered_argv[filtered_argc++] = argv[0];
    for (int i = 1; i < argc; i++)
    {

        filtered_argv[filtered_argc++] = argv[i];
    }
    filtered_argv[filtered_argc] = NULL;

    rc = bio_daemon_main(filtered_argc, filtered_argv);

    free(filtered_argv);
    return rc;
}
