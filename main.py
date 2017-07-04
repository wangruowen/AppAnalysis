#!/usr/bin/env python

import sys

sys.path.append("/usr/local/bin")

import hashlib
import time
import argparse
import logging
import base64
import re
import pprint
from enum import IntEnum
from sklearn.feature_extraction import DictVectorizer
import androlyze as ag  # Androguard


FEATURES = IntEnum("FEATURES",
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
                    certificates
                    signatures
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
                    services
                    providers
                    intent_filters
                """ +
                # File info
                """
                    files_with_types
                    num_of_files
                    images
                    num_of_images
                    libraries
                    num_of_libraries
                    embed_jar_files
                    embed_elf_files
                """)


def prepare_arg_parser():
    myparser = argparse.ArgumentParser()
    myparser.add_argument("-a", "--apk", dest="apk_path", default=None,
                          help="Specify the APK file path to analyze")
    return myparser


def get_value_or_null_if_error(this_obj, func_name, key, f_dict, func_arg_list=None, additional_func=None):
    if this_obj is None:
        raise Exception("Object is null")

    # AnalyzeAPK may generate list of analysis objects
    if type(this_obj) is list:
        obj_list = this_obj
    else:
        obj_list = [this_obj]

    for each_obj in obj_list:
        try:
            func = getattr(each_obj, func_name)
            if func_arg_list is not None:
                value = func(*func_arg_list)
            else:
                value = func()
            if additional_func is not None:
                value = additional_func(value)
            if key in f_dict:
                # key already exists, we append the new value to existing one
                exist_value = f_dict[key]
                if type(exist_value) is list:
                    f_dict[key].extend(value)
                elif type(exist_value) is dict:
                    f_dict[key].update(value)
            else:
                f_dict[key] = value
        except Exception:
            logging.exception("Fail to call func: %s for key: %s! Assign null value"
                              % (func_name, key))
            f_dict[key] = "null"


def parse_value_for_new_feature_or_null_if_error(f_dict, key, new_key, parse_func):
    try:
        f_dict[new_key] = parse_func(f_dict[key])
    except Exception:
        if key not in f_dict:
            logging.error("Key: %s not found in feature set. Cannot parse it to generate new key: %s", key, new_key)
        logging.exception("Fail to parse value from key: %s to new_key: %s", key, new_key)


def get_app_icon_base64(apk, f):
    try:
        icon_file_raw = apk.get_file(apk.get_app_icon())
        icon_base64 = base64.b64encode(icon_file_raw)
        f[FEATURES.icon] = icon_base64
    except Exception:
        logging.exception("Fail to get icon in Base64")


def get_package_info(apk, dex, analysis, f):
    """
    Get the basic info of an APK.

    :param apk:
    :param dex:
    :param analysis:
    :param f:
    :return:
    """
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
    get_app_icon_base64(apk, f)


def get_permissions(apk, dex, analysis, f):
    logging.info("get_permissions")
    get_value_or_null_if_error(apk, "get_requested_aosp_permissions", FEATURES.request_aosp_permissions, f)
    get_value_or_null_if_error(apk, "get_requested_third_party_permissions", FEATURES.request_3rd_permissions, f)
    get_value_or_null_if_error(apk, "get_declared_permissions", FEATURES.declare_new_permissions, f)
    # TODO Dangerous Permissions and Privileged Permissions


def get_intent_filters(apk, f):
    filters = {}
    try:
        for i in apk.get_activities():
            filters.update(apk.get_intent_filters("activity", i))
        for i in apk.get_services():
            filters.update(apk.get_intent_filters("service", i))
        for i in apk.get_receivers():
            filters.update(apk.get_intent_filters("receiver", i))
        f[FEATURES.intent_filters] = filters
    except Exception:
        logging.exception("Fail to get intent filters")


def get_component_info(apk, dex, analysis, f):
    logging.info("get_component_info")
    get_value_or_null_if_error(apk, "get_main_activity", FEATURES.main_activity, f)
    get_value_or_null_if_error(apk, "get_activities", FEATURES.activities, f)
    get_value_or_null_if_error(apk, "get_receivers", FEATURES.receivers, f)
    get_value_or_null_if_error(apk, "get_providers", FEATURES.providers, f)
    get_value_or_null_if_error(apk, "get_services", FEATURES.services, f)
    get_intent_filters(apk, f)


def get_file_info(apk, dex, analysis, f):
    logging.info("get_file_info")
    get_value_or_null_if_error(apk, "get_files_types", FEATURES.files_with_types, f)
    parse_value_for_new_feature_or_null_if_error(f, FEATURES.files_with_types, FEATURES.num_of_files, parse_func=len)
    get_value_or_null_if_error(apk, "get_libraries", FEATURES.libraries, f)
    parse_value_for_new_feature_or_null_if_error(f, FEATURES.libraries, FEATURES.num_of_libraries, parse_func=len)

    image_files = []
    apk_jar_files = []
    elf_so_files = []
    for each_file, each_type in f[FEATURES.files_with_types].iteritems():
        if "image data" in each_type:
            image_files.append(each_file)
        elif "Java archive data" in each_type:
            apk_jar_files.append(each_file)
        elif "ELF " in each_type:
            elf_so_files.append(each_file)

    f[FEATURES.images] = image_files
    f[FEATURES.num_of_images] = len(image_files)
    f[FEATURES.embed_jar_files] = apk_jar_files
    f[FEATURES.embed_elf_files] = elf_so_files


def get_behavior_info(apk, dex, analysis, f):
    logging.info("get_behavior_info")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    start_time = time.time()
    parser = prepare_arg_parser()
    args = parser.parse_args()

    if args.apk_path is not None:
        logging.info("AnalyzeAPK using Androguard ...")
        # dex and analysis can be either instance or list of instances
        apk, dex, analysis = ag.AnalyzeAPK(args.apk_path)

        feature_dict = {}
        get_package_info(apk, dex, analysis, feature_dict)
        get_permissions(apk, dex, analysis, feature_dict)
        get_component_info(apk, dex, analysis, feature_dict)
        get_file_info(apk, dex, analysis, feature_dict)
        get_behavior_info(apk, dex, analysis, feature_dict)

        pprint.pprint(feature_dict, width=1)
    else:
        logging.error("APK file path is None!")
        exit(-1)

    elapsed_time = time.time() - start_time
    days = int(time.strftime("%d", time.gmtime(elapsed_time))) - 1  # days are count from 01 since 1970-01-01
    logging.info("Time spent: "
                 + ("%d days " % days if days > 0 else "")
                 + time.strftime("%H:%M:%S", time.gmtime(elapsed_time)))
