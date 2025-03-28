"""
Unit tests for cfm_facade.py.

To execute them run:
utils/unittest_suite.py \
    autotest_lib.client.cros.multimedia.cfm_facade_unittest
"""

# pylint: disable=missing-docstring

import unittest
from unittest import mock

from autotest_lib.client.common_lib import error
# Mock cros and graphics modules as they import telemetry which is not available
# in unit tests.
cros_mock = mock.Mock()
graphics_mock = mock.Mock()
modules = {'autotest_lib.client.common_lib.cros': cros_mock,
           'autotest_lib.client.cros.graphics': graphics_mock}
with mock.patch.dict('sys.modules', modules):
    from autotest_lib.client.cros.multimedia import cfm_facade

BACKGROUD_PAGE = '_generated_background_page.html'
HANGOUT_WINDOW_0 = 'hangoutswindow.html?windowid=0'


def create_mock_context(url):
    ctx = mock.Mock()
    ctx.GetUrl.return_value = url
    return ctx


class CfmFacadeLocalUnitTest(unittest.TestCase):

    def setUp(self):
        self.facade_resource = mock.Mock()
        self.browser = self.facade_resource._browser
        self.screen = 'hotrod'
        self.cfm_facade = cfm_facade.CFMFacadeLocal(
            self.facade_resource, self.screen)
        cfm_facade.CFMFacadeLocal._DEFAULT_TIMEOUT = 1
        self.extension_path = 'chrome-extension://' + self.cfm_facade._EXT_ID

    @mock.patch.object(cfm_facade, 'kiosk_utils')
    def test_check_hangout_extension_context(self, mock_kiosk_utils):
        stub_ctx = create_mock_context('foo.bar?screen=stub')
        stub_ctx.EvaluateJavaScript.return_value = (
                '%s/%s' % (self.extension_path, HANGOUT_WINDOW_0))

        mock_kiosk_utils.wait_for_kiosk_ext.return_value = [stub_ctx]
        self.cfm_facade.check_hangout_extension_context()
        mock_kiosk_utils.wait_for_kiosk_ext.assert_called_with(self.browser,
            self.cfm_facade._EXT_ID)

    @mock.patch.object(cfm_facade, 'kiosk_utils')
    def test_webview_context_property(self, mock_kiosk_utils):
        stub_ctx = create_mock_context('foo.bar?screen=stub')
        hotrod_ctx = create_mock_context('www.qbc?screen=%s' % self.screen)
        mock_kiosk_utils.get_webview_contexts.return_value = [
                stub_ctx, hotrod_ctx
        ]
        self.assertEqual(self.cfm_facade._webview_context, hotrod_ctx)
        mock_kiosk_utils.get_webview_contexts.assert_called_with(self.browser,
            self.cfm_facade._EXT_ID)

    @mock.patch.object(cfm_facade, 'kiosk_utils')
    def test_get_webview_context_by_screen_two_screens(self, mock_kiosk_utils):
        screen_param = 'foo'
        stub_ctx = create_mock_context('foo.bar?screen=stub')
        hotrod_ctx = create_mock_context('www.qbc?screen=%s' % screen_param)
        mock_kiosk_utils.get_webview_contexts.return_value = [
                stub_ctx, hotrod_ctx
        ]
        found_ctx = self.cfm_facade._get_webview_context_by_screen(screen_param)
        self.assertEqual(found_ctx, hotrod_ctx)

    @mock.patch.object(cfm_facade, 'kiosk_utils')
    def test_get_webview_context_by_screen_only_hotrod_screen(self,
                                                              mock_kiosk_utils):
        screen_param = 'foo'
        stub_ctx = create_mock_context('foo.bar?screen=stub')
        hotrod_ctx = create_mock_context('www.qbc?screen=%s' % screen_param)
        mock_kiosk_utils.get_webview_contexts.return_value = [hotrod_ctx]
        found_ctx = self.cfm_facade._get_webview_context_by_screen(screen_param)
        self.assertEqual(found_ctx, hotrod_ctx)

    @mock.patch.object(cfm_facade, 'kiosk_utils')
    def test_get_webview_context_by_screen_with_mimo_and_main_screen(
            self, mock_kiosk_utils):
        screen_param = 'foo'
        mimo_ctx = create_mock_context('www.qbc?screen=control')
        hotrod_ctx = create_mock_context('www.qbc?screen=%s' % screen_param)
        mock_kiosk_utils.get_webview_contexts.return_value = [hotrod_ctx,
                                                              mimo_ctx]
        found_ctx = self.cfm_facade._get_webview_context_by_screen(screen_param)
        self.assertEqual(found_ctx, hotrod_ctx)

    @mock.patch.object(cfm_facade, 'kiosk_utils')
    def test_get_webview_context_during_oobe_with_two_screens(self,
                                                              mock_kiosk_utils):
        screen_param = 'foo'
        node_screen_ctx = create_mock_context(
            'node.screen.com?screen=hotrod&nooobestatesync&oobedone')
        main_screen_ctx = create_mock_context(
            'mimo.screen.com?screen=%s' % screen_param)
        mock_kiosk_utils.get_webview_contexts.return_value = [
            node_screen_ctx, main_screen_ctx]
        found_ctx = self.cfm_facade._get_webview_context_by_screen(screen_param)
        self.assertEqual(found_ctx, main_screen_ctx)

    @mock.patch.object(cfm_facade, 'kiosk_utils')
    def test_get_webview_context_no_screen_found(self, mock_kiosk_utils):
        foo_ctx = create_mock_context('node.screen.com?screen=foo')
        bar_ctx = create_mock_context('mimo.screen.com?screen=bar')
        mock_kiosk_utils.get_webview_contexts.return_value = [foo_ctx, bar_ctx]
        with self.assertRaises(error.TestFail):
            self.cfm_facade._get_webview_context_by_screen('unknown_param')

    @mock.patch.object(cfm_facade, 'kiosk_utils')
    def test_reboot_device_with_chrome_api(self, mock_kiosk_utils):
        stub_ctx = create_mock_context('foo.bar?screen=stub')
        stub_ctx.EvaluateJavaScript.return_value = (
                '%s/%s' % (self.extension_path, BACKGROUD_PAGE))
        mock_kiosk_utils.wait_for_kiosk_ext.return_value = [stub_ctx]
        self.cfm_facade.reboot_device_with_chrome_api()
        stub_ctx.ExecuteJavaScript.assert_called_with(
                'chrome.runtime.restart();')

    @mock.patch.object(cfm_facade, 'kiosk_utils')
    def test_large_integers_in_media_info_data_points(self, mock_kiosk_utils):
        hotrod_ctx = create_mock_context('www.qbc?screen=%s' % self.screen)
        mock_kiosk_utils.get_webview_contexts.return_value = [hotrod_ctx]
        hotrod_ctx.EvaluateJavaScript.return_value = [{
                'a': 123,
                'b': {
                        'c': 2**31 - 1,
                        'd': 2**31
                }
        }, [-123]]
        data_points = self.cfm_facade.get_media_info_data_points()
        self.assertIsInstance(data_points[0]['a'], int)
        self.assertIsInstance(data_points[0]['b']['c'], int)
        self.assertIsInstance(data_points[0]['b']['d'], float)
        self.assertIsInstance(data_points[1][0], int)
