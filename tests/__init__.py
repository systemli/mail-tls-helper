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


class TestBase(unittest.TestCase):

    def test_load_module(self):
        self.assertTrue(hasattr(mail_tls_helper, 'postfixParseLog'))
