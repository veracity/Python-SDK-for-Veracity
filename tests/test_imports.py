

def test_import_platform():
    import veracity_platform
    print(dir(veracity_platform))


def test_import_base():
    from veracity_platform import base
    print(dir(base))


def test_import_data():
    from veracity_platform import data
    print(dir(data))


def test_import_identity():
    from veracity_platform import identity
    print(dir(identity))


def test_import_iot():
    from veracity_platform import iot
    print(dir(iot))


def test_import_service():
    from veracity_platform import service
    print(dir(service))
