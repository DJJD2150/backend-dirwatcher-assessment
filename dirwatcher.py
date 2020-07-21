#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""This program monitors a given directory for text files that are created
within the monitored directory.  It will continuously search within all
files in the directory for a given "magic string" (implemented with a timed
polling loop).  If the magic string is found in a file, the program will
log a message indicating which file, and the line number within the file
where the magic text was found; it will not be logged again unless it
appears in the file as another subsequent line entry later on."""

import logging
import logging.handlers
import sys
import signal
import time
import argparse
import os
import errno

__author__ = """DJJD2150, the #after-hours-work Slack group video 7/7/2020."""

logger = logging.getLogger(__name__)

files = {}
exit_flag = False


def magic_word_finder(path, start_line, magic_word):
    """Shows a file of a given type plus where to start and searches for
    given text."""
    logger.info(f"searching {path} for instances of {magic_word}")
    line_number = 0
    with open(path) as f:
        for line_number, line in enumerate(f):
            if line_number >= start_line:
                if magic_word in line:
                    logger.info(f"Match found for {magic_word} found on line"
                                f"{line_number + 1} in {path}")
    return line_number + 1


def watch_directory(args):
    """Watches the given directory for added files and deleted files,
    if the directory doesn't exist then it creates the directory."""
    file_list = os.listdir(args.directory)
    detect_added_files(file_list, args.extension)
    detect_removed_files(file_list)
    for f in files:
        path = os.path.join(args.directory, f)
        files[f] = magic_word_finder(
            path,
            files[f],
            args.magic_word
        )


def detect_added_files(file_list, ext):
    """Checks the given directory to see if the new file was added."""
    global files
    for f in file_list:
        if f.endswith(ext) and f not in files:
            files[f] = 0
            logger.info(f"{f} added to watchlist.")
    return file_list


def detect_removed_files(file_list):
    """Checks the given directory to see if a file was deleted."""
    global files
    for f in list(files):
        if f not in file_list:
            logger.info(f"{f} removed from watchlist.")
            del files[f]
    return file_list


def signal_handler(sig_num, frame):
    """
    This is a handler for SIGTERM and SIGINT. Other signals can be mapped
    here as well (SIGHUP?) Basically, it just sets a global flag, and
    main() will exit its loop if the signal is trapped.
    :param sig_num: The integer signal number that was trapped from the OS.
    :param frame: Not used
    :return None
    """
    # log the associated signal name
    logger.warning('Received ' + signal.Signals(sig_num).name)
    global exit_flag
    exit_flag = True


def create_parser():
    """Creates an argument parser object."""
    parser = argparse.ArgumentParser(
        description='Watch a directory of text files for a magic string.'
    )
    parser.add_argument('-i',
                        '--interval',
                        help="""Sets the interval in seconds to check the
                        directory for magic words.""",
                        type=float,
                        default=1.0)
    parser.add_argument('-x', '--extension',
                        help='Sets the type of file to watch for.',
                        type=str,
                        default='.txt')
    parser.add_argument('directory', help='Directory to monitor.')
    parser.add_argument('magic_word', help='The magic word(s) to watch for.')
    return parser


def main(args):
    """Main function declared as standalone for testing."""
    parser = create_parser()
    parsed_args = parser.parse_args(args)
    polling_interval = parsed_args.interval
    logging.basicConfig(
        format='%(asctime)s.%(msecs)03d %(name)-12s '
               '%(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d &%H:%M:%S'
    )
    logger.setLevel(logging.DEBUG)
    start_time = time.time()
    logger.info(
        '\n'
        '-------------------------------------\n'
        f'   Running {__file__}\n'
        f'   PID is {os.getpid()}\n'
        f'   Started on {start_time:.1f}\n'
        '-------------------------------------\n'
    )
    logger.info(
        f'Matching directory:{parsed_args.directory},'
        f'File Extension:{parsed_args.extension},'
        f'Polling Interval:{parsed_args.interval},'
        f'Magic Text:{parsed_args.magic_word}'
    )
    # Hooks into the two signals from the OS
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    while not exit_flag:
        try:
            watch_directory(parsed_args)
        except OSError as e:
            if e.errno == errno.ENOENT:
                logger.error(f"{parsed_args.directory} directory not found")
                time.sleep(2)
            else:
                logger.error(e)
        except Exception as e:
            raise
            logger.error(f"Unhandled exception: {e}")
        time.sleep(polling_interval)

    full_time = time.time() - start_time
    logger.info(
        '\n'
        '------------------------------------------------\n'
        f'   Stopped {__file__}\n'
        f'   Uptime was {full_time:.1f}\n'
        '------------------------------------------------\n'
    )
    logging.shutdown()


if __name__ == "__main__":
    """Runs the main loop until an interrupt input such as control + C
    is used."""
    # logger.info("My Pid is {}".format(os.getpid()))
    # logger.info("Command line arguments: {}".format(sys.argv))
    main(sys.argv[1:])
