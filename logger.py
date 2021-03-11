#!/usr/bin/env python3

__author__ = 'Chariton Karamitas <huku@census-labs.com>'


import logging


_ROOT_LOGGER_NAME = 'exploit'

_ROOT_LOGGER = None


def get_root_logger():

    global _ROOT_LOGGER

    if _ROOT_LOGGER is None:

        _ROOT_LOGGER = logging.getLogger(_ROOT_LOGGER_NAME)
        _ROOT_LOGGER.setLevel(logging.DEBUG)

        formatter = logging.Formatter(fmt='(%(asctime)s) [*] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S')

        handler = logging.FileHandler('%s.log' % _ROOT_LOGGER_NAME)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(formatter)
        _ROOT_LOGGER.addHandler(handler)

        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(formatter)
        _ROOT_LOGGER.addHandler(handler)

    return _ROOT_LOGGER


def get_logger(name):
    return logging.getLogger('%s.%s' % (get_root_logger().name, name))


def shutdown():
    logging.shutdown()

