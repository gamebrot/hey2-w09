# -*- coding: utf-8 -*-
# Copyright 2015 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Configuration options for various cbuildbot builders."""

from __future__ import print_function

import copy
import itertools
import json
import numbers
import os
import re

from autotest_lib.utils.frozen_chromite.lib import constants
from autotest_lib.utils.frozen_chromite.lib import osutils
from autotest_lib.utils.frozen_chromite.utils import memoize

GS_PATH_DEFAULT = 'default'  # Means gs://chromeos-image-archive/ + bot_id

# Contains the valid build config suffixes.
CONFIG_TYPE_RELEASE = 'release'
CONFIG_TYPE_FULL = 'full'
CONFIG_TYPE_FIRMWARE = 'firmware'
CONFIG_TYPE_FACTORY = 'factory'
CONFIG_TYPE_TOOLCHAIN = 'toolchain'

# DISPLAY labels are used to group related builds together in the GE UI.

DISPLAY_LABEL_TRYJOB = 'tryjob'
DISPLAY_LABEL_INCREMENATAL = 'incremental'
DISPLAY_LABEL_FULL = 'full'
DISPLAY_LABEL_CHROME_INFORMATIONAL = 'chrome_informational'
DISPLAY_LABEL_INFORMATIONAL = 'informational'
DISPLAY_LABEL_RELEASE = 'release'
DISPLAY_LABEL_CHROME_PFQ = 'chrome_pfq'
DISPLAY_LABEL_MST_ANDROID_PFQ = 'mst_android_pfq'
DISPLAY_LABEL_VMMST_ANDROID_PFQ = 'vmmst_android_pfq'
DISPLAY_LABEL_PI_ANDROID_PFQ = 'pi_android_pfq'
DISPLAY_LABEL_QT_ANDROID_PFQ = 'qt_android_pfq'
DISPLAY_LABEL_RVC_ANDROID_PFQ = 'rvc_android_pfq'
DISPLAY_LABEL_VMRVC_ANDROID_PFQ = 'vmrvc_android_pfq'
DISPLAY_LABEL_FIRMWARE = 'firmware'
DISPLAY_LABEL_FACTORY = 'factory'
DISPLAY_LABEL_TOOLCHAIN = 'toolchain'
DISPLAY_LABEL_UTILITY = 'utility'
DISPLAY_LABEL_PRODUCTION_TRYJOB = 'production_tryjob'

# This list of constants should be kept in sync with GoldenEye code.
ALL_DISPLAY_LABEL = {
    DISPLAY_LABEL_TRYJOB,
    DISPLAY_LABEL_INCREMENATAL,
    DISPLAY_LABEL_FULL,
    DISPLAY_LABEL_CHROME_INFORMATIONAL,
    DISPLAY_LABEL_INFORMATIONAL,
    DISPLAY_LABEL_RELEASE,
    DISPLAY_LABEL_CHROME_PFQ,
    DISPLAY_LABEL_MST_ANDROID_PFQ,
    DISPLAY_LABEL_VMMST_ANDROID_PFQ,
    DISPLAY_LABEL_PI_ANDROID_PFQ,
    DISPLAY_LABEL_QT_ANDROID_PFQ,
    DISPLAY_LABEL_RVC_ANDROID_PFQ,
    DISPLAY_LABEL_VMRVC_ANDROID_PFQ,
    DISPLAY_LABEL_FIRMWARE,
    DISPLAY_LABEL_FACTORY,
    DISPLAY_LABEL_TOOLCHAIN,
    DISPLAY_LABEL_UTILITY,
    DISPLAY_LABEL_PRODUCTION_TRYJOB,
}

# These values must be kept in sync with the ChromeOS LUCI builders.
#
# https://chrome-internal.googlesource.com/chromeos/
#     infra/config/+/refs/heads/master/luci/cr-buildbucket.cfg
LUCI_BUILDER_FACTORY = 'Factory'
LUCI_BUILDER_FULL = 'Full'
LUCI_BUILDER_INCREMENTAL = 'Incremental'
LUCI_BUILDER_INFORMATIONAL = 'Informational'
LUCI_BUILDER_INFRA = 'Infra'
LUCI_BUILDER_LEGACY_RELEASE = 'LegacyRelease'
LUCI_BUILDER_PFQ = 'PFQ'
LUCI_BUILDER_RAPID = 'Rapid'
LUCI_BUILDER_RELEASE = 'Release'
LUCI_BUILDER_STAGING = 'Staging'
LUCI_BUILDER_TRY = 'Try'

ALL_LUCI_BUILDER = {
    LUCI_BUILDER_FACTORY,
    LUCI_BUILDER_FULL,
    LUCI_BUILDER_INCREMENTAL,
    LUCI_BUILDER_INFORMATIONAL,
    LUCI_BUILDER_INFRA,
    LUCI_BUILDER_LEGACY_RELEASE,
    LUCI_BUILDER_PFQ,
    LUCI_BUILDER_RAPID,
    LUCI_BUILDER_RELEASE,
    LUCI_BUILDER_STAGING,
    LUCI_BUILDER_TRY,
}


def isTryjobConfig(build_config):
    """Is a given build config a tryjob config, or a production config?

  Args:
    build_config: A fully populated instance of BuildConfig.

  Returns:
    Boolean. True if it's a tryjob config.
  """
    return build_config.luci_builder in [LUCI_BUILDER_RAPID, LUCI_BUILDER_TRY]

# In the Json, this special build config holds the default values for all
# other configs.
DEFAULT_BUILD_CONFIG = '_default'

# Constants for config template file
CONFIG_TEMPLATE_BOARDS = 'boards'
CONFIG_TEMPLATE_NAME = 'name'
CONFIG_TEMPLATE_EXPERIMENTAL = 'experimental'
CONFIG_TEMPLATE_LEADER_BOARD = 'leader_board'
CONFIG_TEMPLATE_BOARD_GROUP = 'board_group'
CONFIG_TEMPLATE_BUILDER = 'builder'
CONFIG_TEMPLATE_RELEASE = 'RELEASE'
CONFIG_TEMPLATE_CONFIGS = 'configs'
CONFIG_TEMPLATE_ARCH = 'arch'
CONFIG_TEMPLATE_RELEASE_BRANCH = 'release_branch'
CONFIG_TEMPLATE_REFERENCE_BOARD_NAME = 'reference_board_name'
CONFIG_TEMPLATE_MODELS = 'models'
CONFIG_TEMPLATE_MODEL_NAME = 'name'
CONFIG_TEMPLATE_MODEL_BOARD_NAME = 'board_name'
CONFIG_TEMPLATE_MODEL_TEST_SUITES = 'test_suites'
CONFIG_TEMPLATE_MODEL_CQ_TEST_ENABLED = 'cq_test_enabled'

CONFIG_X86_INTERNAL = 'X86_INTERNAL'
CONFIG_X86_EXTERNAL = 'X86_EXTERNAL'
CONFIG_ARM_INTERNAL = 'ARM_INTERNAL'
CONFIG_ARM_EXTERNAL = 'ARM_EXTERNAL'


def IsCanaryMaster(builder_run):
    """Returns True if this build type is master-release"""
    return (builder_run.config.build_type == constants.CANARY_TYPE
            and builder_run.config.master
            and builder_run.manifest_branch == 'master')


def IsPFQType(b_type):
    """Returns True if this build type is a PFQ."""
    return b_type in (constants.PFQ_TYPE, constants.ANDROID_PFQ_TYPE)


def IsCanaryType(b_type):
    """Returns True if this build type is a Canary."""
    return b_type == constants.CANARY_TYPE


def IsMasterAndroidPFQ(config):
    """Returns True if this build is master Android PFQ type."""
    return config.build_type == constants.ANDROID_PFQ_TYPE and config.master


def GetHWTestEnv(builder_run_config, model_config=None, suite_config=None):
    """Return the env of a suite to run for a given build/model.

  Args:
    builder_run_config: The BuildConfig object inside a BuilderRun object.
    model_config: A ModelTestConfig object to test against.
    suite_config: A HWTestConfig object to test against.

  Returns:
    A string variable to indiate the hwtest environment.
  """
    enable_suite = True if suite_config is None else suite_config.enable_skylab
    enable_model = True if model_config is None else model_config.enable_skylab
    if (builder_run_config.enable_skylab_hw_tests and enable_suite
                and enable_model):
        return constants.ENV_SKYLAB

    return constants.ENV_AUTOTEST


class AttrDict(dict):
    """Dictionary with 'attribute' access.

  This is identical to a dictionary, except that string keys can be addressed as
  read-only attributes.
  """

    def __getattr__(self, name):
        """Support attribute-like access to each dict entry."""
        if name in self:
            return self[name]

        # Super class (dict) has no __getattr__ method, so use __getattribute__.
        return super(AttrDict, self).__getattribute__(name)


class BuildConfig(AttrDict):
    """Dictionary of explicit configuration settings for a cbuildbot config

  Each dictionary entry is in turn a dictionary of config_param->value.

  See DefaultSettings for details on known configurations, and their
  documentation.
  """

    def deepcopy(self):
        """Create a deep copy of this object.

    This is a specialized version of copy.deepcopy() for BuildConfig objects. It
    speeds up deep copies by 10x because we know in advance what is stored
    inside a BuildConfig object and don't have to do as much introspection. This
    function is called a lot during setup of the config objects so optimizing it
    makes a big difference. (It saves seconds off the load time of this module!)
    """
        result = BuildConfig(self)

        # Here is where we handle all values that need deepcopy instead of shallow.
        for k, v in result.items():
            if v is not None:
                if k == 'child_configs':
                    result[k] = [x.deepcopy() for x in v]
                elif k in ('vm_tests', 'vm_tests_override', 'hw_tests',
                           'hw_tests_override', 'tast_vm_tests'):
                    result[k] = [copy.copy(x) for x in v]
                # type(v) is faster than isinstance.
                elif type(v) is list:  # pylint: disable=unidiomatic-typecheck
                    result[k] = v[:]

        return result

    def apply(self, *args, **kwargs):
        """Apply changes to this BuildConfig.

    Note: If an override is callable, it will be called and passed the prior
    value for the given key (or None) to compute the new value.

    Args:
      args: Dictionaries or templates to update this config with.
      kwargs: Settings to inject; see DefaultSettings for valid values.

    Returns:
      self after changes are applied.
    """
        inherits = list(args)
        inherits.append(kwargs)

        for update_config in inherits:
            for name, value in update_config.items():
                if callable(value):
                    # If we are applying to a fixed value, we resolve to a fixed value.
                    # Otherwise, we save off a callable to apply later, perhaps with
                    # nested callables (IE: we curry them). This allows us to use
                    # callables in templates, and apply templates to each other and still
                    # get the expected result when we use them later on.
                    #
                    # Delaying the resolution of callables is safe, because "Add()" always
                    # applies against the default, which has fixed values for everything.

                    if name in self:
                        # apply it to the current value.
                        if callable(self[name]):
                            # If we have no fixed value to resolve with, stack the callables.
                            def stack(new_callable, old_callable):
                                """Helper method to isolate namespace for closure."""
                                return lambda fixed: new_callable(
                                        old_callable(fixed))

                            self[name] = stack(value, self[name])
                        else:
                            # If the current value was a fixed value, apply the callable.
                            self[name] = value(self[name])
                    else:
                        # If we had no value to apply it to, save it for later.
                        self[name] = value

                elif name == '_template':
                    # We never apply _template. You have to set it through Add.
                    pass

                else:
                    # Simple values overwrite whatever we do or don't have.
                    self[name] = value

        return self

    def derive(self, *args, **kwargs):
        """Create a new config derived from this one.

    Note: If an override is callable, it will be called and passed the prior
    value for the given key (or None) to compute the new value.

    Args:
      args: Mapping instances to mixin.
      kwargs: Settings to inject; see DefaultSettings for valid values.

    Returns:
      A new _config instance.
    """
        return self.deepcopy().apply(*args, **kwargs)

    def AddSlave(self, slave):
        """Assign slave config(s) to a build master.

    A helper for adding slave configs to a master config.
    """
        assert self.master
        if self['slave_configs'] is None:
            self['slave_configs'] = []
        self.slave_configs.append(slave.name)
        self.slave_configs.sort()

    def AddSlaves(self, slaves):
        """Assign slave config(s) to a build master.

    A helper for adding slave configs to a master config.
    """
        assert self.master
        if self['slave_configs'] is None:
            self['slave_configs'] = []
        self.slave_configs.extend(slave_config.name for slave_config in slaves)
        self.slave_configs.sort()


class VMTestConfig(object):
    """Config object for virtual machine tests suites.

  Attributes:
    test_type: Test type to be run.
    test_suite: Test suite to be run in VMTest.
    timeout: Number of seconds to wait before timing out waiting for
             results.
    retry: Whether we should retry tests that fail in a suite run.
    max_retries: Integer, maximum job retries allowed at suite level.
                 None for no max.
    warn_only: Boolean, failure on VM tests warns only.
    use_ctest: Use the old ctest code path rather than the new chromite one.
  """
    DEFAULT_TEST_TIMEOUT = 90 * 60

    def __init__(self,
                 test_type,
                 test_suite=None,
                 timeout=DEFAULT_TEST_TIMEOUT,
                 retry=False,
                 max_retries=constants.VM_TEST_MAX_RETRIES,
                 warn_only=False,
                 use_ctest=True):
        """Constructor -- see members above."""
        self.test_type = test_type
        self.test_suite = test_suite
        self.timeout = timeout
        self.retry = retry
        self.max_retries = max_retries
        self.warn_only = warn_only
        self.use_ctest = use_ctest

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


class GCETestConfig(object):
    """Config object for GCE tests suites.

  Attributes:
    test_type: Test type to be run.
    test_suite: Test suite to be run in GCETest.
    timeout: Number of seconds to wait before timing out waiting for
             results.
    use_ctest: Use the old ctest code path rather than the new chromite one.
  """
    DEFAULT_TEST_TIMEOUT = 60 * 60

    def __init__(self,
                 test_type,
                 test_suite=None,
                 timeout=DEFAULT_TEST_TIMEOUT,
                 use_ctest=True):
        """Constructor -- see members above."""
        self.test_type = test_type
        self.test_suite = test_suite
        self.timeout = timeout
        self.use_ctest = use_ctest

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


class TastVMTestConfig(object):
    """Config object for a Tast virtual-machine-based test suite.

  Attributes:
    name: String containing short human-readable name describing test suite.
    test_exprs: List of string expressions describing which tests to run; this
                is passed directly to the 'tast run' command. See
                https://goo.gl/UPNEgT for info about test expressions.
    timeout: Number of seconds to wait before timing out waiting for
             results.
  """
    DEFAULT_TEST_TIMEOUT = 60 * 60

    def __init__(self, suite_name, test_exprs, timeout=DEFAULT_TEST_TIMEOUT):
        """Constructor -- see members above."""
        # This is an easy mistake to make and results in confusing errors later when
        # a list of one-character strings gets passed to the tast command.
        if not isinstance(test_exprs, list):
            raise TypeError('test_exprs must be list of strings')
        self.suite_name = suite_name
        self.test_exprs = test_exprs
        self.timeout = timeout

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


class MoblabVMTestConfig(object):
    """Config object for moblab tests suites.

  Attributes:
    test_type: Test type to be run.
    timeout: Number of seconds to wait before timing out waiting for
             results.
  """
    DEFAULT_TEST_TIMEOUT = 60 * 60

    def __init__(self, test_type, timeout=DEFAULT_TEST_TIMEOUT):
        """Constructor -- see members above."""
        self.test_type = test_type
        self.timeout = timeout

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


class ModelTestConfig(object):
    """Model specific config that controls which test suites are executed.

  Attributes:
    name: The name of the model that will be tested (matches model label)
    lab_board_name: The name of the board in the lab (matches board label)
    test_suites: List of hardware test suites that will be executed.
  """

    def __init__(self,
                 name,
                 lab_board_name,
                 test_suites=None,
                 enable_skylab=True):
        """Constructor -- see members above."""
        self.name = name
        self.lab_board_name = lab_board_name
        self.test_suites = test_suites
        self.enable_skylab = enable_skylab

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


class HWTestConfig(object):
    """Config object for hardware tests suites.

  Attributes:
    suite: Name of the test suite to run.
    timeout: Number of seconds to wait before timing out waiting for
             results.
    pool: Pool to use for hw testing.
    blocking: Setting this to true requires that this suite must PASS for suites
              scheduled after it to run. This also means any suites that are
              scheduled before a blocking one are also blocking ones scheduled
              after. This should be used when you want some suites to block
              whether or not others should run e.g. only run longer-running
              suites if some core ones pass first.

              Note, if you want multiple suites to block other suites but run
              in parallel, you should only mark the last one scheduled as
              blocking (it effectively serves as a thread/process join).
    async: Fire-and-forget suite.
    warn_only: Failure on HW tests warns only (does not generate error).
    critical: Usually we consider structural failures here as OK.
    priority:  Priority at which tests in the suite will be scheduled in
               the hw lab.
    file_bugs: Should we file bugs if a test fails in a suite run.
    minimum_duts: minimum number of DUTs required for testing in the hw lab.
    retry: Whether we should retry tests that fail in a suite run.
    max_retries: Integer, maximum job retries allowed at suite level.
                 None for no max.
    suite_min_duts: Preferred minimum duts. Lab will prioritize on getting such
                    number of duts even if the suite is competing with
                    other suites that have higher priority.
    suite_args: Arguments passed to the suite.  This should be a dict
                representing keyword arguments.  The value is marshalled
                using repr(), so the dict values should be basic types.
    quota_account: The quotascheduler account to use for all tests in this
                   suite.

  Some combinations of member settings are invalid:
    * A suite config may not specify both blocking and async.
    * A suite config may not specify both warn_only and critical.
  """
    _MINUTE = 60
    _HOUR = 60 * _MINUTE
    _DAY = 24 * _HOUR
    # CTS timeout ~ 2 * expected runtime in case other tests are using the CTS
    # pool.
    # Must not exceed the buildbucket build timeout set at
    # https://chrome-internal.googlesource.com/chromeos/infra/config/+/8f12edac54383831aaed9ed1819ef909a66ecc97/testplatform/main.star#90
    CTS_QUAL_HW_TEST_TIMEOUT = int(1 * _DAY + 18 * _HOUR)
    # GTS runs faster than CTS. But to avoid starving GTS by CTS we set both
    # timeouts equal.
    GTS_QUAL_HW_TEST_TIMEOUT = CTS_QUAL_HW_TEST_TIMEOUT
    SHARED_HW_TEST_TIMEOUT = int(3.0 * _HOUR)
    PALADIN_HW_TEST_TIMEOUT = int(2.0 * _HOUR)
    BRANCHED_HW_TEST_TIMEOUT = int(10.0 * _HOUR)

    # TODO(jrbarnette) Async HW test phases complete within seconds.
    # however, the tests they start can require hours to complete.
    # Chromite code doesn't distinguish "timeout for Autotest" from
    # timeout in the builder.  This is WRONG WRONG WRONG.  But, until
    # there's a better fix, we'll allow these phases hours to fail.
    ASYNC_HW_TEST_TIMEOUT = int(250.0 * _MINUTE)

    def __init__(self,
                 suite,
                 pool=constants.HWTEST_QUOTA_POOL,
                 timeout=SHARED_HW_TEST_TIMEOUT,
                 warn_only=False,
                 critical=False,
                 blocking=False,
                 file_bugs=False,
                 priority=constants.HWTEST_BUILD_PRIORITY,
                 retry=True,
                 max_retries=constants.HWTEST_MAX_RETRIES,
                 minimum_duts=0,
                 suite_min_duts=0,
                 suite_args=None,
                 offload_failures_only=False,
                 enable_skylab=True,
                 quota_account=constants.HWTEST_QUOTA_ACCOUNT_BVT,
                 **kwargs):
        """Constructor -- see members above."""
        # Python 3.7+ made async a reserved keyword.
        asynchronous = kwargs.pop('async', False)
        setattr(self, 'async', asynchronous)
        assert not kwargs, 'Excess kwargs found: %s' % (kwargs, )

        assert not asynchronous or not blocking, '%s is async and blocking' % suite
        assert not warn_only or not critical
        self.suite = suite
        self.pool = pool
        self.timeout = timeout
        self.blocking = blocking
        self.warn_only = warn_only
        self.critical = critical
        self.file_bugs = file_bugs
        self.priority = priority
        self.retry = retry
        self.max_retries = max_retries
        self.minimum_duts = minimum_duts
        self.suite_min_duts = suite_min_duts
        self.suite_args = suite_args
        self.offload_failures_only = offload_failures_only
        # Usually whether to run in skylab is controlled by 'enable_skylab_hw_test'
        # in build config. But for some particular suites, we want to exclude them
        # from Skylab even if the build config is migrated to Skylab.
        self.enable_skylab = enable_skylab
        self.quota_account = quota_account

    def _SetCommonBranchedValues(self):
        """Set the common values for branched builds."""
        self.timeout = max(HWTestConfig.BRANCHED_HW_TEST_TIMEOUT, self.timeout)

        # Set minimum_duts default to 0, which means that lab will not check the
        # number of available duts to meet the minimum requirement before creating
        # a suite job for branched build.
        self.minimum_duts = 0

    def SetBranchedValuesForSkylab(self):
        """Set suite values for branched builds for skylab."""
        self._SetCommonBranchedValues()

        if (constants.SKYLAB_HWTEST_PRIORITIES_MAP[self.priority] <
                    constants.SKYLAB_HWTEST_PRIORITIES_MAP[
                            constants.HWTEST_DEFAULT_PRIORITY]):
            self.priority = constants.HWTEST_DEFAULT_PRIORITY

    def SetBranchedValues(self):
        """Changes the HW Test timeout/priority values to branched values."""
        self._SetCommonBranchedValues()

        # Only reduce priority if it's lower.
        new_priority = constants.HWTEST_PRIORITIES_MAP[
                constants.HWTEST_DEFAULT_PRIORITY]
        if isinstance(self.priority, numbers.Integral):
            self.priority = min(self.priority, new_priority)
        elif constants.HWTEST_PRIORITIES_MAP[self.priority] > new_priority:
            self.priority = new_priority

    @property
    def timeout_mins(self):
        return self.timeout // 60

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


class NotificationConfig(object):
    """Config object for defining notification settings.

  Attributes:
    email: Email address that receives failure notifications.
    threshold: Number of consecutive failures that should occur in order to
              be notified. This number should be greater than or equal to 1. If
              none is specified, default is 1.
    template: Email template luci-notify should use when sending the email
              notification. If none is specified, uses the default template.
  """
    DEFAULT_TEMPLATE = 'legacy_release'
    DEFAULT_THRESHOLD = 1

    def __init__(self,
                 email,
                 threshold=DEFAULT_THRESHOLD,
                 template=DEFAULT_TEMPLATE):
        """Constructor -- see members above."""
        self.email = email
        self.threshold = threshold
        self.template = template
        self.threshold = threshold

    @property
    def email_notify(self):
        return {'email': self.email, 'template': self.template}

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


def DefaultSettings():
    # Enumeration of valid settings; any/all config settings must be in this.
    # All settings must be documented.
    return dict(
            # The name of the template we inherit settings from.
            _template=None,

            # The name of the config.
            name=None,

            # A list of boards to build.
            boards=None,

            # A list of ModelTestConfig objects that represent all of the models
            # supported by a given unified build and their corresponding test config.
            models=[],

            # This value defines what part of the Golden Eye UI is responsible for
            # displaying builds of this build config. The value is required, and
            # must be in ALL_DISPLAY_LABEL.
            # TODO: Make the value required after crbug.com/776955 is finished.
            display_label=None,

            # This defines which LUCI Builder to use. It must match an entry in:
            #
            # https://chrome-internal.git.corp.google.com/chromeos/
            #    manifest-internal/+/infra/config/cr-buildbucket.cfg
            #
            luci_builder=LUCI_BUILDER_LEGACY_RELEASE,

            # The profile of the variant to set up and build.
            profile=None,

            # This bot pushes changes to the overlays.
            master=False,

            # A basic_builder is a special configuration which does not perform tests
            # or mutate external config.
            basic_builder=False,

            # If this bot triggers slave builds, this will contain a list of
            # slave config names.
            slave_configs=None,

            # If False, this flag indicates that the CQ should not check whether
            # this bot passed or failed. Set this to False if you are setting up a
            # new bot. Once the bot is on the waterfall and is consistently green,
            # mark the builder as important=True.
            important=True,

            # If True, build config should always be run as if --debug was set
            # on the cbuildbot command line. This is different from 'important'
            # and is usually correlated with tryjob build configs.
            debug=False,

            # If True, use the debug instance of CIDB instead of prod.
            debug_cidb=False,

            # Timeout for the build as a whole (in seconds).
            build_timeout=(5 * 60 + 30) * 60,

            # A list of NotificationConfig objects describing who to notify of builder
            # failures.
            notification_configs=[],

            # An integer. If this builder fails this many times consecutively, send
            # an alert email to the recipients health_alert_recipients. This does
            # not apply to tryjobs. This feature is similar to the ERROR_WATERMARK
            # feature of upload_symbols, and it may make sense to merge the features
            # at some point.
            health_threshold=0,

            # List of email addresses to send health alerts to for this builder. It
            # supports automatic email address lookup for the following sheriff
            # types:
            #     'tree': tree sheriffs
            #     'chrome': chrome gardeners
            health_alert_recipients=[],

            # Whether this is an internal build config.
            internal=False,

            # Whether this is a branched build config. Used for pfq logic.
            branch=False,

            # The name of the manifest to use. E.g., to use the buildtools manifest,
            # specify 'buildtools'.
            manifest=constants.DEFAULT_MANIFEST,

            # emerge use flags to use while setting up the board, building packages,
            # making images, etc.
            useflags=[],

            # Set the variable CHROMEOS_OFFICIAL for the build. Known to affect
            # parallel_emerge, cros_set_lsb_release, and chromeos_version.sh. See
            # bug chromium-os:14649
            chromeos_official=False,

            # Use binary packages for building the toolchain. (emerge --getbinpkg)
            usepkg_toolchain=True,

            # Use binary packages for build_packages and setup_board.
            usepkg_build_packages=True,

            # Does this profile need to sync chrome?  If None, we guess based on
            # other factors.  If True/False, we always do that.
            sync_chrome=None,

            # Use the newest ebuilds for all the toolchain packages.
            latest_toolchain=False,

            # This is only valid when latest_toolchain is True. If you set this to a
            # commit-ish, the gcc ebuild will use it to build the toolchain
            # compiler.
            gcc_githash=None,

            # Wipe and replace the board inside the chroot.
            board_replace=False,

            # Wipe and replace chroot, but not source.
            chroot_replace=True,

            # Create the chroot on a loopback-mounted chroot.img instead of a bare
            # directory.  Required for snapshots; otherwise optional.
            chroot_use_image=True,

            # Uprevs the local ebuilds to build new changes since last stable.
            # build.  If master then also pushes these changes on success. Note that
            # we uprev on just about every bot config because it gives us a more
            # deterministic build system (the tradeoff being that some bots build
            # from source more frequently than if they never did an uprev). This way
            # the release/factory/etc... builders will pick up changes that devs
            # pushed before it runs, but after the corresponding PFQ bot ran (which
            # is what creates+uploads binpkgs).  The incremental bots are about the
            # only ones that don't uprev because they mimic the flow a developer
            # goes through on their own local systems.
            uprev=True,

            # Select what overlays to look at for revving and prebuilts. This can be
            # any constants.VALID_OVERLAYS.
            overlays=constants.PUBLIC_OVERLAYS,

            # Select what overlays to push at. This should be a subset of overlays
            # for the particular builder.  Must be None if not a master.  There
            # should only be one master bot pushing changes to each overlay per
            # branch.
            push_overlays=None,

            # Uprev Android, values of 'latest_release', or None.
            android_rev=None,

            # Which Android branch build do we try to uprev from.
            android_import_branch=None,

            # Android package name.
            android_package=None,

            # Uprev Chrome, values of 'tot', 'stable_release', or None.
            chrome_rev=None,

            # Exit the builder right after checking compilation.
            # TODO(mtennant): Should be something like "compile_check_only".
            compilecheck=False,

            # If True, run DebugInfoTest stage.
            debuginfo_test=False,

            # Runs the tests that the signer would run. This should only be set if
            # 'recovery' is in images.
            signer_tests=False,

            # Runs unittests for packages.
            unittests=True,

            # A list of the packages to blacklist from unittests.
            unittest_blacklist=[],

            # Generates AFDO data. Will capture a profile of chrome using a hwtest
            # to run a predetermined set of benchmarks.
            # FIXME(tcwang): Keep this config during transition to async AFDO
            afdo_generate=False,

            # Generates AFDO data asynchronously. Will capture a profile of chrome
            # using a hwtest to run a predetermined set of benchmarks.
            afdo_generate_async=False,

            # Verify and publish kernel profiles.
            kernel_afdo_verify=False,

            # Verify and publish chrome profiles.
            chrome_afdo_verify=False,

            # Generate Chrome orderfile. Will build Chrome with C3 ordering and
            # generate an orderfile for uploading as a result.
            orderfile_generate=False,

            # Verify unvetted Chrome orderfile. Will use the most recent unvetted
            # orderfile and build Chrome. Upload the orderfile to vetted bucket
            # as a result.
            orderfile_verify=False,

            # Generates AFDO data, builds the minimum amount of artifacts and
            # assumes a non-distributed builder (i.e.: the whole process in a single
            # builder).
            afdo_generate_min=False,

            # Update the Chrome ebuild with the AFDO profile info.
            afdo_update_chrome_ebuild=False,

            # Update the kernel ebuild with the AFDO profile info.
            afdo_update_kernel_ebuild=False,

            # Uses AFDO data. The Chrome build will be optimized using the AFDO
            # profile information found in Chrome's source tree.
            afdo_use=True,

            # A list of VMTestConfig objects to run by default.
            vm_tests=[
                    VMTestConfig(constants.VM_SUITE_TEST_TYPE,
                                 test_suite='smoke'),
                    VMTestConfig(constants.SIMPLE_AU_TEST_TYPE)
            ],

            # A list of all VMTestConfig objects to use if VM Tests are forced on
            # (--vmtest command line or trybot). None means no override.
            vm_tests_override=None,

            # If true, in addition to upload vm test result to artifact folder, report
            # results to other dashboard as well.
            vm_test_report_to_dashboards=False,

            # The number of times to run the VMTest stage. If this is >1, then we
            # will run the stage this many times, stopping if we encounter any
            # failures.
            vm_test_runs=1,

            # If True, run SkylabHWTestStage instead of HWTestStage for suites that
            # use pools other than pool:cts.
            enable_skylab_hw_tests=False,

            # If set, this is the URL of the bug justifying why hw_tests are disabled
            # on a builder that should always have hw_tests.
            hw_tests_disabled_bug='',

            # If True, run SkylabHWTestStage instead of HWTestStage for suites that
            # use pool:cts.
            enable_skylab_cts_hw_tests=False,

            # A list of HWTestConfig objects to run.
            hw_tests=[],

            # A list of all HWTestConfig objects to use if HW Tests are forced on
            # (--hwtest command line or trybot). None means no override.
            hw_tests_override=None,

            # If true, uploads artifacts for hw testing. Upload payloads for test
            # image if the image is built. If not, dev image is used and then base
            # image.
            upload_hw_test_artifacts=True,

            # If true, uploads individual image tarballs.
            upload_standalone_images=True,

            # A list of GCETestConfig objects to use. Currently only some lakitu
            # builders run gce tests.
            gce_tests=[],

            # Whether to run CPEExport stage. This stage generates portage depgraph
            # data that is used for bugs reporting (see go/why-cpeexport). Only
            # release builders should run this stage.
            run_cpeexport=False,

            # Whether to run BuildConfigsExport stage. This stage generates build
            # configs (see crbug.com/974795 project). Only release builders should
            # run this stage.
            run_build_configs_export=False,

            # A list of TastVMTestConfig objects describing Tast-based test suites
            # that should be run in a VM.
            tast_vm_tests=[],

            # Default to not run moblab tests. Currently the blessed moblab board runs
            # these tests.
            moblab_vm_tests=[],

            # List of patterns for portage packages for which stripped binpackages
            # should be uploaded to GS. The patterns are used to search for packages
            # via `equery list`.
            upload_stripped_packages=[
                    # Used by SimpleChrome workflow.
                    'chromeos-base/chromeos-chrome',
                    'sys-kernel/*kernel*',
            ],

            # Google Storage path to offload files to.
            #   None - No upload
            #   GS_PATH_DEFAULT - 'gs://chromeos-image-archive/' + bot_id
            #   value - Upload to explicit path
            gs_path=GS_PATH_DEFAULT,

            # TODO(sosa): Deprecate binary.
            # Type of builder.  Check constants.VALID_BUILD_TYPES.
            build_type=constants.PFQ_TYPE,

            # Whether to schedule test suites by suite_scheduler. Generally only
            # True for "release" builders.
            suite_scheduling=False,

            # The class name used to build this config.  See the modules in
            # cbuildbot / builders/*_builders.py for possible values.  This should
            # be the name in string form -- e.g. "simple_builders.SimpleBuilder" to
            # get the SimpleBuilder class in the simple_builders module.  If not
            # specified, we'll fallback to legacy probing behavior until everyone
            # has been converted (see the scripts/cbuildbot.py file for details).
            builder_class_name=None,

            # List of images we want to build -- see build_image for more details.
            images=['test'],

            # Image from which we will build update payloads.  Must either be None
            # or name one of the images in the 'images' list, above.
            payload_image=None,

            # Whether to build a netboot image.
            factory_install_netboot=True,

            # Whether to build the factory toolkit.
            factory_toolkit=True,

            # Whether to build factory packages in BuildPackages.
            factory=True,

            # Flag to control if all packages for the target are built. If disabled
            # and unittests are enabled, the unit tests and their dependencies
            # will still be built during the testing stage.
            build_packages=True,

            # Tuple of specific packages we want to build.  Most configs won't
            # specify anything here and instead let build_packages calculate.
            packages=[],

            # Do we push a final release image to chromeos-images.
            push_image=False,

            # Do we upload debug symbols.
            upload_symbols=False,

            # Whether we upload a hwqual tarball.
            hwqual=False,

            # Run a stage that generates release payloads for signed images.
            paygen=False,

            # If the paygen stage runs, generate tests, and schedule auto-tests for
            # them.
            paygen_skip_testing=False,

            # If the paygen stage runs, don't generate any delta payloads. This is
            # only done if deltas are broken for a given board.
            paygen_skip_delta_payloads=False,

            # Run a stage that generates and uploads package CPE information.
            cpe_export=True,

            # Run a stage that generates and uploads debug symbols.
            debug_symbols=True,

            # Do not package the debug symbols in the binary package. The debug
            # symbols will be in an archive with the name cpv.debug.tbz2 in
            # /build/${BOARD}/packages and uploaded with the prebuilt.
            separate_debug_symbols=True,

            # Include *.debug files for debugging core files with gdb in debug.tgz.
            # These are very large. This option only has an effect if debug_symbols
            # and archive are set.
            archive_build_debug=False,

            # Run a stage that archives build and test artifacts for developer
            # consumption.
            archive=True,

            # Git repository URL for our manifests.
            #  https://chromium.googlesource.com/chromiumos/manifest
            #  https://chrome-internal.googlesource.com/chromeos/manifest-internal
            manifest_repo_url=None,

            # Whether we are using the manifest_version repo that stores per-build
            # manifests.
            manifest_version=False,

            # Use a different branch of the project manifest for the build.
            manifest_branch=None,

            # LKGM for ChromeOS generated for Chrome builds that are blessed from
            # canary runs.
            use_chrome_lkgm=False,

            # Upload prebuilts for this build. Valid values are PUBLIC, PRIVATE, or
            # False.
            prebuilts=False,

            # Use SDK as opposed to building the chroot from source.
            use_sdk=True,

            # The description string to print out for config when user runs --list.
            description=None,

            # Boolean that enables parameter --git-sync for upload_prebuilts.
            git_sync=False,

            # A list of the child config groups, if applicable. See the AddGroup
            # method.
            child_configs=[],

            # Whether this config belongs to a config group.
            grouped=False,

            # layout of build_image resulting image. See
            # scripts/build_library/legacy_disk_layout.json or
            # overlay-<board>/scripts/disk_layout.json for possible values.
            disk_layout=None,

            # If enabled, run the PatchChanges stage.  Enabled by default. Can be
            # overridden by the --nopatch flag.
            postsync_patch=True,

            # Reexec into the buildroot after syncing.  Enabled by default.
            postsync_reexec=True,

            # Run the binhost_test stage. Only makes sense for builders that have no
            # boards.
            binhost_test=False,

            # If specified, it is passed on to the PushImage script as '--sign-types'
            # commandline argument.  Must be either None or a list of image types.
            sign_types=None,

            # TODO(sosa): Collapse to one option.
            # ========== Dev installer prebuilts options =======================

            # Upload prebuilts for this build to this bucket. If it equals None the
            # default buckets are used.
            binhost_bucket=None,

            # Parameter --key for upload_prebuilts. If it equals None, the default
            # values are used, which depend on the build type.
            binhost_key=None,

            # Parameter --binhost-base-url for upload_prebuilts. If it equals None,
            # the default value is used.
            binhost_base_url=None,

            # Upload dev installer prebuilts.
            dev_installer_prebuilts=False,

            # Enable rootfs verification on the image.
            rootfs_verification=True,

            # Build the Chrome SDK.
            chrome_sdk=False,

            # If chrome_sdk is set to True, this determines whether we attempt to
            # build Chrome itself with the generated SDK.
            chrome_sdk_build_chrome=True,

            # If chrome_sdk is set to True, this determines whether we use goma to
            # build chrome.
            chrome_sdk_goma=True,

            # Run image tests. This should only be set if 'base' is in our list of
            # images.
            image_test=False,

            # ==================================================================
            # Workspace related options.

            # Which branch should WorkspaceSyncStage checkout, if run.
            workspace_branch=None,

            # ==================================================================
            # The documentation associated with the config.
            doc=None,

            # ==================================================================
            # The goma related options.

            # Which goma client to use.
            goma_client_type=None,

            # Try to use goma to build all packages.
            build_all_with_goma=False,

            # This is a LUCI Scheduler schedule string. Setting this will create
            # a LUCI Scheduler for this build on swarming (not buildbot).
            # See: https://goo.gl/VxSzFf
            schedule=None,

            # This is the list of git repos which can trigger this build in swarming.
            # Implies that schedule is set, to "triggered".
            # The format is of the form:
            #   [ (<git repo url>, (<ref1>, <ref2>, …)),
            #    …]
            triggered_gitiles=None,

            # If true, skip package retries in BuildPackages step.
            nobuildretry=False,

            # Attempt to run this build on the same bot each time it builds.
            # This is only meaningful for slave builds run on swarming. This
            # should only be used with LUCI Builders that use a reserved
            # role to avoid having bots stolen by other builds while
            # waiting on a new master build.
            build_affinity=False,
    )


def GerritInstanceParameters(name, instance):
    param_names = [
            '_GOB_INSTANCE', '_GERRIT_INSTANCE', '_GOB_HOST', '_GERRIT_HOST',
            '_GOB_URL', '_GERRIT_URL'
    ]

    gob_instance = instance
    gerrit_instance = '%s-review' % instance
    gob_host = constants.GOB_HOST % gob_instance
    gerrit_host = constants.GOB_HOST % gerrit_instance
    gob_url = 'https://%s' % gob_host
    gerrit_url = 'https://%s' % gerrit_host

    params = [
            gob_instance, gerrit_instance, gob_host, gerrit_host, gob_url,
            gerrit_url
    ]

    return dict([('%s%s' % (name, pn), p)
                 for pn, p in zip(param_names, params)])


def DefaultSiteParameters():
    # Enumeration of valid site parameters; any/all site parameters must be here.
    # All site parameters should be documented.
    default_site_params = {}

    manifest_project = 'chromiumos/manifest'
    manifest_int_project = 'chromeos/manifest-internal'
    external_remote = 'cros'
    internal_remote = 'cros-internal'
    chromium_remote = 'chromium'
    chrome_remote = 'chrome'
    aosp_remote = 'aosp'
    weave_remote = 'weave'

    internal_change_prefix = 'chrome-internal:'
    external_change_prefix = 'chromium:'

    # Gerrit instance site parameters.
    default_site_params.update(GerritInstanceParameters(
            'EXTERNAL', 'chromium'))
    default_site_params.update(
            GerritInstanceParameters('INTERNAL', 'chrome-internal'))
    default_site_params.update(GerritInstanceParameters('AOSP', 'android'))
    default_site_params.update(GerritInstanceParameters('WEAVE', 'weave'))

    default_site_params.update(
            # Parameters to define which manifests to use.
            MANIFEST_PROJECT=manifest_project,
            MANIFEST_INT_PROJECT=manifest_int_project,
            MANIFEST_PROJECTS=(manifest_project, manifest_int_project),
            MANIFEST_URL=os.path.join(default_site_params['EXTERNAL_GOB_URL'],
                                      manifest_project),
            MANIFEST_INT_URL=os.path.join(
                    default_site_params['INTERNAL_GERRIT_URL'],
                    manifest_int_project),

            # CrOS remotes specified in the manifests.
            EXTERNAL_REMOTE=external_remote,
            INTERNAL_REMOTE=internal_remote,
            GOB_REMOTES={
                    default_site_params['EXTERNAL_GOB_INSTANCE']:
                    external_remote,
                    default_site_params['INTERNAL_GOB_INSTANCE']:
                    internal_remote,
            },
            CHROMIUM_REMOTE=chromium_remote,
            CHROME_REMOTE=chrome_remote,
            AOSP_REMOTE=aosp_remote,
            WEAVE_REMOTE=weave_remote,

            # Only remotes listed in CROS_REMOTES are considered branchable.
            # CROS_REMOTES and BRANCHABLE_PROJECTS must be kept in sync.
            GERRIT_HOSTS={
                    external_remote:
                    default_site_params['EXTERNAL_GERRIT_HOST'],
                    internal_remote:
                    default_site_params['INTERNAL_GERRIT_HOST'],
                    aosp_remote: default_site_params['AOSP_GERRIT_HOST'],
                    weave_remote: default_site_params['WEAVE_GERRIT_HOST'],
            },
            CROS_REMOTES={
                    external_remote: default_site_params['EXTERNAL_GOB_URL'],
                    internal_remote: default_site_params['INTERNAL_GOB_URL'],
                    aosp_remote: default_site_params['AOSP_GOB_URL'],
                    weave_remote: default_site_params['WEAVE_GOB_URL'],
            },
            GIT_REMOTES={
                    chromium_remote: default_site_params['EXTERNAL_GOB_URL'],
                    chrome_remote: default_site_params['INTERNAL_GOB_URL'],
                    external_remote: default_site_params['EXTERNAL_GOB_URL'],
                    internal_remote: default_site_params['INTERNAL_GOB_URL'],
                    aosp_remote: default_site_params['AOSP_GOB_URL'],
                    weave_remote: default_site_params['WEAVE_GOB_URL'],
            },

            # Prefix to distinguish internal and external changes. This is used
            # when a user specifies a patch with "-g", when generating a key for
            # a patch to use in our PatchCache, and when displaying a custom
            # string for the patch.
            INTERNAL_CHANGE_PREFIX=internal_change_prefix,
            EXTERNAL_CHANGE_PREFIX=external_change_prefix,
            CHANGE_PREFIX={
                    external_remote: external_change_prefix,
                    internal_remote: internal_change_prefix,
            },

            # List of remotes that are okay to include in the external manifest.
            EXTERNAL_REMOTES=(
                    external_remote,
                    chromium_remote,
                    aosp_remote,
                    weave_remote,
            ),

            # Mapping 'remote name' -> regexp that matches names of repositories on
            # that remote that can be branched when creating CrOS branch.
            # Branching script will actually create a new git ref when branching
            # these projects. It won't attempt to create a git ref for other projects
            # that may be mentioned in a manifest. If a remote is missing from this
            # dictionary, all projects on that remote are considered to not be
            # branchable.
            BRANCHABLE_PROJECTS={
                    external_remote: r'(chromiumos|aosp)/(.+)',
                    internal_remote: r'chromeos/(.+)',
            },

            # Additional parameters used to filter manifests, create modified
            # manifests, and to branch manifests.
            MANIFEST_VERSIONS_GOB_URL=(
                    '%s/chromiumos/manifest-versions' %
                    default_site_params['EXTERNAL_GOB_URL']),
            MANIFEST_VERSIONS_GOB_URL_TEST=(
                    '%s/chromiumos/manifest-versions-test' %
                    default_site_params['EXTERNAL_GOB_URL']),
            MANIFEST_VERSIONS_INT_GOB_URL=(
                    '%s/chromeos/manifest-versions' %
                    default_site_params['INTERNAL_GOB_URL']),
            MANIFEST_VERSIONS_INT_GOB_URL_TEST=(
                    '%s/chromeos/manifest-versions-test' %
                    default_site_params['INTERNAL_GOB_URL']),
            MANIFEST_VERSIONS_GS_URL='gs://chromeos-manifest-versions',

            # Standard directories under buildroot for cloning these repos.
            EXTERNAL_MANIFEST_VERSIONS_PATH='manifest-versions',
            INTERNAL_MANIFEST_VERSIONS_PATH='manifest-versions-internal',

            # GS URL in which to archive build artifacts.
            ARCHIVE_URL='gs://chromeos-image-archive',
    )

    return default_site_params


class SiteConfig(dict):
    """This holds a set of named BuildConfig values."""

    def __init__(self, defaults=None, templates=None):
        """Init.

    Args:
      defaults: Dictionary of key value pairs to use as BuildConfig values.
                All BuildConfig values should be defined here. If None,
                the DefaultSettings() is used. Most sites should use
                DefaultSettings(), and then update to add any site specific
                values needed.
      templates: Dictionary of template names to partial BuildConfigs
                 other BuildConfigs can be based on. Mostly used to reduce
                 verbosity of the config dump file format.
    """
        super(SiteConfig, self).__init__()
        self._defaults = DefaultSettings()
        if defaults:
            self._defaults.update(defaults)
        self._templates = AttrDict() if templates is None else AttrDict(
                templates)

    def GetDefault(self):
        """Create the canonical default build configuration."""
        # Enumeration of valid settings; any/all config settings must be in this.
        # All settings must be documented.
        return BuildConfig(**self._defaults)

    def GetTemplates(self):
        """Get the templates of the build configs"""
        return self._templates

    @property
    def templates(self):
        return self._templates

    #
    # Methods for searching a SiteConfig's contents.
    #
    def GetBoards(self):
        """Return an iterable of all boards in the SiteConfig."""
        return set(
                itertools.chain.from_iterable(x.boards for x in self.values()
                                              if x.boards))

    def FindFullConfigsForBoard(self, board=None):
        """Returns full builder configs for a board.

    Args:
      board: The board to match. By default, match all boards.

    Returns:
      A tuple containing a list of matching external configs and a list of
      matching internal release configs for a board.
    """
        ext_cfgs = []
        int_cfgs = []

        for name, c in self.items():
            if c['boards'] and (board is None or board in c['boards']):
                if name.endswith(
                        '-%s' % CONFIG_TYPE_RELEASE) and c['internal']:
                    int_cfgs.append(c.deepcopy())
                elif name.endswith(
                        '-%s' % CONFIG_TYPE_FULL) and not c['internal']:
                    ext_cfgs.append(c.deepcopy())

        return ext_cfgs, int_cfgs

    def FindCanonicalConfigForBoard(self, board, allow_internal=True):
        """Get the canonical cbuildbot builder config for a board."""
        ext_cfgs, int_cfgs = self.FindFullConfigsForBoard(board)
        # If both external and internal builds exist for this board, prefer the
        # internal one unless instructed otherwise.
        both = (int_cfgs if allow_internal else []) + ext_cfgs

        if not both:
            raise ValueError('Invalid board specified: %s.' % board)
        return both[0]

    def GetSlaveConfigMapForMaster(self,
                                   master_config,
                                   options=None,
                                   important_only=True):
        """Gets the slave builds triggered by a master config.

    If a master builder also performs a build, it can (incorrectly) return
    itself.

    Args:
      master_config: A build config for a master builder.
      options: The options passed on the commandline. This argument is required
      for normal operation, but we accept None to assist with testing.
      important_only: If True, only get the important slaves.

    Returns:
      A slave_name to slave_config map, corresponding to the slaves for the
      master represented by master_config.

    Raises:
      AssertionError if the given config is not a master config or it does
        not have a manifest_version.
    """
        assert master_config.master
        assert master_config.slave_configs is not None

        slave_name_config_map = {}
        if options is not None and options.remote_trybot:
            return {}

        # Look up the build configs for all slaves named by the master.
        slave_name_config_map = {
                name: self[name]
                for name in master_config.slave_configs
        }

        if important_only:
            # Remove unimportant configs from the result.
            slave_name_config_map = {
                    k: v
                    for k, v in slave_name_config_map.items() if v.important
            }

        return slave_name_config_map

    def GetSlavesForMaster(self,
                           master_config,
                           options=None,
                           important_only=True):
        """Get a list of qualified build slave configs given the master_config.

    Args:
      master_config: A build config for a master builder.
      options: The options passed on the commandline. This argument is optional,
               and only makes sense when called from cbuildbot.
      important_only: If True, only get the important slaves.
    """
        slave_map = self.GetSlaveConfigMapForMaster(
                master_config, options=options, important_only=important_only)
        return list(slave_map.values())

    #
    # Methods used when creating a Config programmatically.
    #
    def Add(self, name, template=None, *args, **kwargs):
        """Add a new BuildConfig to the SiteConfig.

    Examples:
      # Creates default build named foo.
      site_config.Add('foo')

      # Creates default build with board 'foo_board'
      site_config.Add('foo',
                      boards=['foo_board'])

      # Creates build based on template_build for 'foo_board'.
      site_config.Add('foo',
                      template_build,
                      boards=['foo_board'])

      # Creates build based on template for 'foo_board'. with mixin.
      # Inheritance order is default, template, mixin, arguments.
      site_config.Add('foo',
                      template_build,
                      mixin_build_config,
                      boards=['foo_board'])

      # Creates build without a template but with mixin.
      # Inheritance order is default, template, mixin, arguments.
      site_config.Add('foo',
                      None,
                      mixin_build_config,
                      boards=['foo_board'])

    Args:
      name: The name to label this configuration; this is what cbuildbot
            would see.
      template: BuildConfig to use as a template for this build.
      args: BuildConfigs to patch into this config. First one (if present) is
            considered the template. See AddTemplate for help on templates.
      kwargs: BuildConfig values to explicitly set on this config.

    Returns:
      The BuildConfig just added to the SiteConfig.
    """
        assert name not in self, ('%s already exists.' % name)

        inherits, overrides = args, kwargs
        if template:
            inherits = (template, ) + inherits

        # Make sure we don't ignore that argument silently.
        if '_template' in overrides:
            raise ValueError('_template cannot be explicitly set.')

        result = self.GetDefault()
        result.apply(*inherits, **overrides)

        # Select the template name based on template argument, or nothing.
        resolved_template = template.get('_template') if template else None
        assert not resolved_template or resolved_template in self.templates, \
            '%s inherits from non-template %s' % (name, resolved_template)

        # Our name is passed as an explicit argument. We use the first build
        # config as our template, or nothing.
        result['name'] = name
        result['_template'] = resolved_template
        self[name] = result
        return result

    def AddWithoutTemplate(self, name, *args, **kwargs):
        """Add a config containing only explicitly listed values (no defaults)."""
        self.Add(name, None, *args, **kwargs)

    def AddGroup(self, name, *args, **kwargs):
        """Create a new group of build configurations.

    Args:
      name: The name to label this configuration; this is what cbuildbot
            would see.
      args: Configurations to build in this group. The first config in
            the group is considered the primary configuration and is used
            for syncing and creating the chroot.
      kwargs: Override values to use for the parent config.

    Returns:
      A new BuildConfig instance.
    """
        child_configs = [x.deepcopy().apply(grouped=True) for x in args]
        return self.Add(name, args[0], child_configs=child_configs, **kwargs)

    def AddForBoards(self,
                     suffix,
                     boards,
                     per_board=None,
                     template=None,
                     *args,
                     **kwargs):
        """Create configs for all boards in |boards|.

    Args:
      suffix: Config name is <board>-<suffix>.
      boards: A list of board names as strings.
      per_board: A dictionary of board names to BuildConfigs, or None.
      template: The template to use for all configs created.
      *args: Mixin templates to apply.
      **kwargs: Additional keyword arguments to be used in AddConfig.

    Returns:
      List of the configs created.
    """
        result = []

        for board in boards:
            config_name = '%s-%s' % (board, suffix)

            # Insert the per_board value as the last mixin, if it exists.
            mixins = args + (dict(boards=[board]), )
            if per_board and board in per_board:
                mixins = mixins + (per_board[board], )

            # Create the new config for this board.
            result.append(self.Add(config_name, template, *mixins, **kwargs))

        return result

    def ApplyForBoards(self, suffix, boards, *args, **kwargs):
        """Update configs for all boards in |boards|.

    Args:
      suffix: Config name is <board>-<suffix>.
      boards: A list of board names as strings.
      *args: Mixin templates to apply.
      **kwargs: Additional keyword arguments to be used in AddConfig.

    Returns:
      List of the configs updated.
    """
        result = []

        for board in boards:
            config_name = '%s-%s' % (board, suffix)
            assert config_name in self, ('%s does not exist.' % config_name)

            # Update the config for this board.
            result.append(self[config_name].apply(*args, **kwargs))

        return result

    def AddTemplate(self, name, *args, **kwargs):
        """Create a template named |name|.

    Templates are used to define common settings that are shared across types
    of builders. They help reduce duplication in config_dump.json, because we
    only define the template and its settings once.

    Args:
      name: The name of the template.
      args: See the docstring of BuildConfig.derive.
      kwargs: See the docstring of BuildConfig.derive.
    """
        assert name not in self._templates, ('Template %s already exists.' %
                                             name)

        template = BuildConfig()
        template.apply(*args, **kwargs)
        template['_template'] = name
        self._templates[name] = template

        return template

    def _MarshalBuildConfig(self, name, config):
        """Hide the defaults from a given config entry.

    Args:
      name: Default build name (usually dictionary key).
      config: A config entry.

    Returns:
      The same config entry, but without any defaults.
    """
        defaults = self.GetDefault()
        defaults['name'] = name

        template = config.get('_template')
        if template:
            defaults.apply(self._templates[template])
            defaults['_template'] = None

        result = {}
        for k, v in config.items():
            if defaults.get(k) != v:
                if k == 'child_configs':
                    result['child_configs'] = [
                            self._MarshalBuildConfig(name, child)
                            for child in v
                    ]
                else:
                    result[k] = v

        return result

    def _MarshalTemplates(self):
        """Return a version of self._templates with only used templates.

    Templates have callables/delete keys resolved against GetDefault() to
    ensure they can be safely saved to json.

    Returns:
      Dict copy of self._templates with all unreferenced templates removed.
    """
        defaults = self.GetDefault()

        # All templates used. We ignore child configs since they
        # should exist at top level.
        used = set(c.get('_template', None) for c in self.values())
        used.discard(None)

        result = {}

        for name in used:
            # Expand any special values (callables, etc)
            expanded = defaults.derive(self._templates[name])
            # Recover the '_template' value which is filtered out by derive.
            expanded['_template'] = name
            # Hide anything that matches the default.
            save = {k: v for k, v in expanded.items() if defaults.get(k) != v}
            result[name] = save

        return result

    def SaveConfigToString(self):
        """Save this Config object to a Json format string."""
        default = self.GetDefault()

        config_dict = {}
        config_dict['_default'] = default
        config_dict['_templates'] = self._MarshalTemplates()
        for k, v in self.items():
            config_dict[k] = self._MarshalBuildConfig(k, v)

        return PrettyJsonDict(config_dict)

    def SaveConfigToFile(self, config_file):
        """Save this Config to a Json file.

    Args:
      config_file: The file to write too.
    """
        json_string = self.SaveConfigToString()
        osutils.WriteFile(config_file, json_string)

    def DumpExpandedConfigToString(self):
        """Dump the SiteConfig to Json with all configs full expanded.

    This is intended for debugging default/template behavior. The dumped JSON
    can't be reloaded (at least not reliably).
    """
        return PrettyJsonDict(self)

    def DumpConfigCsv(self):
        """Dump the SiteConfig to CSV with all configs fully expanded.

    This supports configuration analysis and debugging.
    """
        raw_config = json.loads(self.DumpExpandedConfigToString())
        header_keys = {'builder_name', 'test_type', 'device'}
        csv_rows = []
        for builder_name, values in raw_config.items():
            row = {'builder_name': builder_name}
            tests = {}
            raw_devices = []
            for key, value in values.items():
                header_keys.add(key)
                if value:
                    if isinstance(value, list):
                        if '_tests' in key:
                            tests[key] = value
                        elif key == 'models':
                            raw_devices = value
                        else:
                            # Ignoring this for now for test analysis.
                            if key != 'child_configs':
                                row[key] = ' | '.join(
                                        str(array_val) for array_val in value)
                    else:
                        row[key] = value

            if tests:
                for test_type, test_entries in tests.items():
                    for test_entry in test_entries:
                        test_row = copy.deepcopy(row)
                        test_row['test_type'] = test_type
                        raw_test = json.loads(test_entry)
                        for test_key, test_value in raw_test.items():
                            if test_value:
                                header_keys.add(test_key)
                                test_row[test_key] = test_value
                        csv_rows.append(test_row)
                        if raw_devices:
                            for raw_device in raw_devices:
                                device = json.loads(raw_device)
                                test_suite = test_row.get('suite', '')
                                test_suites = device.get('test_suites', [])
                                if test_suite and test_suites and test_suite in test_suites:
                                    device_row = copy.deepcopy(test_row)
                                    device_row['device'] = device['name']
                                    csv_rows.append(device_row)
            else:
                csv_rows.append(row)

        csv_result = [','.join(header_keys)]
        for csv_row in csv_rows:
            row_values = []
            for header_key in header_keys:
                row_values.append('"%s"' % str(csv_row.get(header_key, '')))
            csv_result.append(','.join(row_values))

        return '\n'.join(csv_result)


#
# Functions related to working with GE Data.
#


def LoadGEBuildConfigFromFile(
    build_settings_file=constants.GE_BUILD_CONFIG_FILE):
    """Load template config dict from a Json encoded file."""
    json_string = osutils.ReadFile(build_settings_file)
    return json.loads(json_string)


def GeBuildConfigAllBoards(ge_build_config):
    """Extract a list of board names from the GE Build Config.

  Args:
    ge_build_config: Dictionary containing the decoded GE configuration file.

  Returns:
    A list of board names as strings.
  """
    return [b['name'] for b in ge_build_config['boards']]


def GetUnifiedBuildConfigAllBuilds(ge_build_config):
    """Extract a list of all unified build configurations.

  This dictionary is based on the JSON defined by the proto generated from
  GoldenEye.  See cs/crosbuilds.proto

  Args:
    ge_build_config: Dictionary containing the decoded GE configuration file.

  Returns:
    A list of unified build configurations (json configs)
  """
    return ge_build_config.get('reference_board_unified_builds', [])


class BoardGroup(object):
    """Class holds leader_boards and follower_boards for grouped boards"""

    def __init__(self):
        self.leader_boards = []
        self.follower_boards = []

    def AddLeaderBoard(self, board):
        self.leader_boards.append(board)

    def AddFollowerBoard(self, board):
        self.follower_boards.append(board)

    def __str__(self):
        return ('Leader_boards: %s Follower_boards: %s' %
                (self.leader_boards, self.follower_boards))


def GroupBoardsByBuilderAndBoardGroup(board_list):
    """Group boards by builder and board_group.

  Args:
    board_list: board list from the template file.

  Returns:
    builder_group_dict: maps builder to {group_n: board_group_n}
    builder_ungrouped_dict: maps builder to a list of ungrouped boards
  """
    builder_group_dict = {}
    builder_ungrouped_dict = {}

    for b in board_list:
        name = b[CONFIG_TEMPLATE_NAME]
        # Invalid build configs being written out with no config templates,
        # thus the default. See https://crbug.com/1012278.
        for config in b.get(CONFIG_TEMPLATE_CONFIGS, []):
            board = {'name': name}
            board.update(config)

            builder = config[CONFIG_TEMPLATE_BUILDER]
            if builder not in builder_group_dict:
                builder_group_dict[builder] = {}
            if builder not in builder_ungrouped_dict:
                builder_ungrouped_dict[builder] = []

            board_group = config[CONFIG_TEMPLATE_BOARD_GROUP]
            if not board_group:
                builder_ungrouped_dict[builder].append(board)
                continue
            if board_group not in builder_group_dict[builder]:
                builder_group_dict[builder][board_group] = BoardGroup()
            if config[CONFIG_TEMPLATE_LEADER_BOARD]:
                builder_group_dict[builder][board_group].AddLeaderBoard(board)
            else:
                builder_group_dict[builder][board_group].AddFollowerBoard(
                        board)

    return (builder_group_dict, builder_ungrouped_dict)


def GroupBoardsByBuilder(board_list):
    """Group boards by the 'builder' flag."""
    builder_to_boards_dict = {}

    for b in board_list:
        # Invalid build configs being written out with no configs array, thus the
        # default. See https://crbug.com/1005803.
        for config in b.get(CONFIG_TEMPLATE_CONFIGS, []):
            builder = config[CONFIG_TEMPLATE_BUILDER]
            if builder not in builder_to_boards_dict:
                builder_to_boards_dict[builder] = set()
            builder_to_boards_dict[builder].add(b[CONFIG_TEMPLATE_NAME])

    return builder_to_boards_dict


def GetNonUniBuildLabBoardName(board):
    """Return the board name labeled in the lab for non-unibuild."""
    # Those special string represent special configuration used in the image,
    # and should run on DUT without those string.
    # We strip those string from the board so that lab can handle it correctly.
    SPECIAL_SUFFIX = [
            '-arcnext$',
            '-arcvm$',
            '-arc-r$',
            '-arc-r-userdebug$',
            '-connectivitynext$',
            '-kernelnext$',
            '-kvm$',
            '-ndktranslation$',
            '-cfm$',
            '-campfire$',
            '-borealis$',
    ]
    # ARM64 userspace boards use 64 suffix but can't put that in list above
    # because of collisions with boards like kevin-arc64.
    ARM64_BOARDS = ['cheza64', 'kevin64']
    for suffix in SPECIAL_SUFFIX:
        board = re.sub(suffix, '', board)
    if board in ARM64_BOARDS:
        # Remove '64' suffix from the board name.
        board = board[:-2]
    return board


def GetArchBoardDict(ge_build_config):
    """Get a dict mapping arch types to board names.

  Args:
    ge_build_config: Dictionary containing the decoded GE configuration file.

  Returns:
    A dict mapping arch types to board names.
  """
    arch_board_dict = {}

    for b in ge_build_config[CONFIG_TEMPLATE_BOARDS]:
        board_name = b[CONFIG_TEMPLATE_NAME]
        # Invalid build configs being written out with no configs array, thus the
        # default. See https://crbug.com/947712.
        for config in b.get(CONFIG_TEMPLATE_CONFIGS, []):
            arch = config[CONFIG_TEMPLATE_ARCH]
            arch_board_dict.setdefault(arch, set()).add(board_name)

    for b in GetUnifiedBuildConfigAllBuilds(ge_build_config):
        board_name = b[CONFIG_TEMPLATE_REFERENCE_BOARD_NAME]
        arch = b[CONFIG_TEMPLATE_ARCH]
        arch_board_dict.setdefault(arch, set()).add(board_name)

    return arch_board_dict


#
# Functions related to loading/saving Json.
#
class ObjectJSONEncoder(json.JSONEncoder):
    """Json Encoder that encodes objects as their dictionaries."""

    # pylint: disable=method-hidden
    def default(self, o):
        return self.encode(o.__dict__)


def PrettyJsonDict(dictionary):
    """Returns a pretty-ified json dump of a dictionary."""
    return json.dumps(dictionary,
                      cls=ObjectJSONEncoder,
                      sort_keys=True,
                      indent=4,
                      separators=(',', ': ')) + '\n'


def LoadConfigFromFile(config_file=constants.CHROMEOS_CONFIG_FILE):
    """Load a Config a Json encoded file."""
    json_string = osutils.ReadFile(config_file)
    return LoadConfigFromString(json_string)


def LoadConfigFromString(json_string):
    """Load a cbuildbot config from it's Json encoded string."""
    config_dict = json.loads(json_string)

    # Use standard defaults, but allow the config to override.
    defaults = DefaultSettings()
    defaults.update(config_dict.pop(DEFAULT_BUILD_CONFIG))
    _DeserializeConfigs(defaults)

    templates = config_dict.pop('_templates', {})
    for t in templates.values():
        _DeserializeConfigs(t)

    defaultBuildConfig = BuildConfig(**defaults)

    builds = {
            n: _CreateBuildConfig(n, defaultBuildConfig, v, templates)
            for n, v in config_dict.items()
    }

    # config is the struct that holds the complete cbuildbot config.
    result = SiteConfig(defaults=defaults, templates=templates)
    result.update(builds)

    return result


def _DeserializeConfig(build_dict,
                       config_key,
                       config_class,
                       preserve_none=False):
    """Deserialize config of given type inside build_dict.

  Args:
    build_dict: The build_dict to update (in place)
    config_key: Key for the config inside build_dict.
    config_class: The class to instantiate for the config.
    preserve_none: If True, None values are preserved as is. By default, they
        are dropped.
  """
    serialized_configs = build_dict.pop(config_key, None)
    if serialized_configs is None:
        if preserve_none:
            build_dict[config_key] = None
        return

    deserialized_configs = []
    for config_string in serialized_configs:
        if isinstance(config_string, config_class):
            deserialized_config = config_string
        else:
            # Each test config is dumped as a json string embedded in json.
            embedded_configs = json.loads(config_string)
            deserialized_config = config_class(**embedded_configs)
        deserialized_configs.append(deserialized_config)
    build_dict[config_key] = deserialized_configs


def _DeserializeConfigs(build_dict):
    """Updates a config dictionary with recreated objects.

  Notification configs and various test configs are serialized as strings
  (rather than JSON objects), so we need to turn them into real objects before
  they can be consumed.

  Args:
    build_dict: The config dictionary to update (in place).
  """
    _DeserializeConfig(build_dict, 'vm_tests', VMTestConfig)
    _DeserializeConfig(build_dict,
                       'vm_tests_override',
                       VMTestConfig,
                       preserve_none=True)
    _DeserializeConfig(build_dict, 'models', ModelTestConfig)
    _DeserializeConfig(build_dict, 'hw_tests', HWTestConfig)
    _DeserializeConfig(build_dict,
                       'hw_tests_override',
                       HWTestConfig,
                       preserve_none=True)
    _DeserializeConfig(build_dict, 'gce_tests', GCETestConfig)
    _DeserializeConfig(build_dict, 'tast_vm_tests', TastVMTestConfig)
    _DeserializeConfig(build_dict, 'moblab_vm_tests', MoblabVMTestConfig)
    _DeserializeConfig(build_dict, 'notification_configs', NotificationConfig)


def _CreateBuildConfig(name, default, build_dict, templates):
    """Create a BuildConfig object from it's parsed JSON dictionary encoding."""
    # These build config values need special handling.
    child_configs = build_dict.pop('child_configs', None)
    template = build_dict.get('_template')

    # Use the name passed in as the default build name.
    build_dict.setdefault('name', name)

    result = default.deepcopy()
    # Use update to explicitly avoid apply's special handing.
    if template:
        result.update(templates[template])
    result.update(build_dict)

    _DeserializeConfigs(result)

    if child_configs is not None:
        result['child_configs'] = [
                _CreateBuildConfig(name, default, child, templates)
                for child in child_configs
        ]

    return result


@memoize.Memoize
def GetConfig():
    """Load the current SiteConfig.

  Returns:
    SiteConfig instance to use for this build.
  """
    return LoadConfigFromFile(constants.CHROMEOS_CONFIG_FILE)


@memoize.Memoize
def GetSiteParams():
    """Get the site parameter configs.

  This is the new, preferred method of accessing the site parameters, instead of
  SiteConfig.params.

  Returns:
    AttrDict of site parameters
  """
    site_params = AttrDict()
    site_params.update(DefaultSiteParameters())
    return site_params


def append_useflags(useflags):
    """Used to append a set of useflags to existing useflags.

  Useflags that shadow prior use flags will cause the prior flag to be removed.
  (e.g. appending '-foo' to 'foo' will cause 'foo' to be removed)

  Examples:
    new_config = base_config.derive(useflags=append_useflags(['foo', '-bar'])

  Args:
    useflags: List of string useflags to append.
  """
    assert isinstance(useflags, (list, set))
    shadowed_useflags = {
            '-' + flag
            for flag in useflags if not flag.startswith('-')
    }
    shadowed_useflags.update(
            {flag[1:]
             for flag in useflags if flag.startswith('-')})

    def handler(old_useflags):
        new_useflags = set(old_useflags or [])
        new_useflags.update(useflags)
        new_useflags.difference_update(shadowed_useflags)
        return sorted(list(new_useflags))

    return handler
