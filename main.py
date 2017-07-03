#!/usr/bin/env python

import sys

sys.path.append("/usr/local/bin")

import hashlib
import time
import argparse
import logging
import base64
from enum import Enum
import androlyze as ag  # Androguard


FEATURES = Enum("FEATURES",
                # Package basics
                """
                    pkg_name
                    app_name
                    version_code
                    version_name
                    apk_size
                    apk_md5
                    apk_sha1
                    android_manifest
                    max_sdk_version
                    min_sdk_version
                    strings
                    icon
                """ +
                # Permissions
                """
                    request_aosp_permissions
                    request_3rd_permissions
                    declare_new_permissions
                    dangerous_permissions
                    privileged_permissions
                """ +
                # Four major components
                """
                    main_activity
                    activities
                    receivers
                    providers
                    services
                    intent_filters
                """ +
                # File info
                """
                    files
                    num_of_files
                    images
                    num_of_images
                    libraries
                    num_of_libraries
                """)


def prepare_arg_parser():
    myparser = argparse.ArgumentParser()
    myparser.add_argument("-a", "--apk", dest="apk_path", default=None,
                          help="Specify the APK file path to analyze")
    return myparser


def get_value_or_null_if_error(this_obj, func_name, key, f_dict, additional_func=None):
    if this_obj is None:
        raise Exception("Object is null")

    try:
        func = getattr(this_obj, func_name)
        value = func()
        if additional_func is not None:
            f_dict[key] = additional_func(value)
        else:
            f_dict[key] = value
    except Exception:
        logging.exception("Fail to call func: %s for key: %s! Assign null value"
                          % (func_name, key))
        f_dict[key] = "null"


def get_app_icon_base64(apk, f):
    try:
        icon_file_raw = apk.get_file(apk.get_app_icon())
        icon_base64 = base64.b64encode(icon_file_raw)
        f[FEATURES.icon] = icon_base64
    except Exception:
        logging.exception("Fail to get icon in Base64")


def get_package_info(apk, dex, analysis, f):
    logging.info("get_package_info")
    get_value_or_null_if_error(apk, "get_package", FEATURES.pkg_name, f)
    get_value_or_null_if_error(apk, "get_app_name", FEATURES.app_name, f)
    get_value_or_null_if_error(apk, "get_androidversion_code", FEATURES.version_code, f)
    get_value_or_null_if_error(apk, "get_androidversion_name", FEATURES.version_name, f)
    get_value_or_null_if_error(apk, "get_raw", FEATURES.apk_size, f, additional_func=len)
    get_value_or_null_if_error(apk, "get_raw", FEATURES.apk_md5, f,
                               additional_func=lambda x: hashlib.md5(x).hexdigest())
    get_value_or_null_if_error(apk, "get_raw", FEATURES.apk_sha1, f,
                               additional_func=lambda x: hashlib.sha1(x).hexdigest())
    get_value_or_null_if_error(apk, "get_android_manifest_xml", FEATURES.android_manifest, f,
                               additional_func=lambda x: x.toxml())
    get_value_or_null_if_error(apk, "get_max_sdk_version", FEATURES.max_sdk_version, f)
    get_value_or_null_if_error(apk, "get_min_sdk_version", FEATURES.min_sdk_version, f)
    get_value_or_null_if_error(dex, "get_strings", FEATURES.strings, f)
    get_value_or_null_if_error(apk, "get_files", FEATURES.files, f)
    get_app_icon_base64(apk, f)


def get_permissions(apk, dex, analysis, f):
    logging.info("get_permissions")
    get_value_or_null_if_error(apk, "get_requested_aosp_permissions", FEATURES.request_aosp_permissions, f)
    get_value_or_null_if_error(apk, "get_requested_third_party_permissions", FEATURES.request_3rd_permissions, f)
    get_value_or_null_if_error(apk, "get_declared_permissions", FEATURES.declare_new_permissions, f)
    # TODO Dangerous Permissions and Privileged Permissions


def get_component_info(apk, dex, analysis, f):
    logging.info("get_component_info")
    get_value_or_null_if_error(apk, "get_main_activity", FEATURES.main_activity, f)
    get_value_or_null_if_error(apk, "get_activities", FEATURES.activites, f)
    get_value_or_null_if_error(apk, "get_receivers", FEATURES.receivers, f)
    get_value_or_null_if_error(apk, "get_providers", FEATURES.providers, f)
    get_value_or_null_if_error(apk, "get_services", FEATURES.services, f)


def get_file_info(apk, dex, analysis, f):
    logging.info("get_component_info")


def get_behavior_info(apk, dex, analysis, f):
    logging.info("get_behavior_info")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    start_time = time.time()
    parser = prepare_arg_parser()
    args = parser.parse_args()

    if args.apk_path is not None:
        apk, dex, analysis = ag.AnalyzeAPK(args.apk_path)
        feature_dict = {}
        get_package_info(apk, dex, analysis, feature_dict)
        get_permissions(apk, dex, analysis, feature_dict)
        get_component_info(apk, dex, analysis, feature_dict)
        get_file_info(apk, dex, analysis, feature_dict)
        get_behavior_info(apk, dex, analysis, feature_dict)
    else:
        logging.error("APK file path is None!")
        exit(-1)

    elapsed_time = time.time() - start_time
    days = int(time.strftime("%d", time.gmtime(elapsed_time))) - 1  # days are count from 01 since 1970-01-01
    logging.info("Time spent: "
                 + ("%d days " % days if days > 0 else "")
                 + time.strftime("%H:%M:%S", time.gmtime(elapsed_time)))
