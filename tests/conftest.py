def pytest_addoption(parser):
    parser.addoption(
        "--authority-test-backend",
        metavar="MODULE:FACTORY",
        help="Test-only unregistered backend factory; never changes production registration",
    )
