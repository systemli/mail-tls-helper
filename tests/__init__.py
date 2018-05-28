import os
import unittest


TESTS_DIR = os.path.realpath(os.path.dirname(__file__))
MAIL_TLS_FILENAME = os.path.realpath(os.path.join(TESTS_DIR, os.path.pardir, 'mail-tls-helper.py'))


def import_module_by_filename(module_name, filename):
    """ import a given python source file (defined by its filename) as a module

    @param module_name: this name will be attached to the __name__ of the resulting module
    @param filename: location of the python file to be loaded
    """
    try:
        import importlib.util
        is_python3 = True
    except ImportError:
        import imp
        is_python3 = False
    if is_python3:
        spec = importlib.util.spec_from_file_location(module_name, filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    else:
        return imp.load_source(module_name, filename)


# access the functions of the module under test via this manually imported module
mail_tls_helper = import_module_by_filename('mail_tls_helper', MAIL_TLS_FILENAME)


def _get_relay_stats(**kwargs):
    result = mail_tls_helper.relayFactory()
    result.update(**kwargs)
    return result


class TestBase(unittest.TestCase):
    """ common class for all tests (containing some helper methods) """

    def _get_asset_filename(self, name):
        return os.path.join(TESTS_DIR, 'assets', name)

    def assertRelayDictCounts(self, relay_dict, count_dict):
        """ verify that the sums of specific attributes are equal to the expectated values

        count_dict: mapping of relay dictionary keys to their expected sum (over all relays)
        """
        for count_name, wanted_value in count_dict.items():
            real_count = sum(relay[count_name] for relay in relay_dict.values())
            self.assertEqual(real_count, wanted_value)

    def parse_postfix_log_from_assets(self, filename):
        with open(self._get_asset_filename(filename), 'r') as test_file:
            return mail_tls_helper.postfixParseLog(test_file, set())


class TestCode(TestBase):
    def test_load_module(self):
        self.assertTrue(hasattr(mail_tls_helper, 'postfixParseLog'))


class TestPostfixParser(TestBase):

    def test_parse_sent_count(self):
        relay_dict = self.parse_postfix_log_from_assets('postfix_count_sent.log')
        self.assertRelayDictCounts(relay_dict, {'sentCount': 1, 'tlsCount': 0})
        self.assertEqual(relay_dict, {
            'relay.example.org': _get_relay_stats(domains={'dest.example.org'}, sentCount=1)})

    def test_parse_sent_tls_count(self):
        relay_dict = self.parse_postfix_log_from_assets('postfix_count_sent_with_tls.log')
        self.assertRelayDictCounts(relay_dict, {'sentCount': 1, 'sentCountTLS': 1})
        self.assertEqual(relay_dict, {
            'relay.example.org': _get_relay_stats(domains={'dest.example.org'},
                                                  sentCount=1, sentCountTLS=1, isTLS=True)})
