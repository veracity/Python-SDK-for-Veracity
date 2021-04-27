""" Setup script for the Veracity Python SDK.
"""

import sys
import os
import os.path
from setuptools import setup

__author__ = 'DNV'
__copyright__ = 'DNV'
__licence__ = 'MIT Licence'
__maintainer__ = 'Veracity Team'
__email__ = 'veracity@dnv.com'
__url__ = 'https://github.com/veracity/Python-SDK-for-Veracity'

version = "0.0.2a1"

if __name__ == '__main__':
    # Build a list of all files to be included in the Python package folder.
    package_data = []
    package_data.append('LICENCE')
    package_data = {'veracity_platform': package_data}

    setup(
        name='veracity-platform',
        version=version,
        author=__author__,
        # author_email=__email__,
        maintainer=__maintainer__,
        maintainer_email=__email__,
        url=__url__,
        description='DNV Veracity platform SDK',
        long_description=(
            'Software development kit for the DNV Veracity platform. Provides'
            'programmatic access to the IDP and platform REST API.'
        ),
        license=__licence__,
        packages=['veracity_platform'],
        package_dir={'': 'src'},
        package_data=package_data,
        install_requires=[
            'aiohttp',
            'msal',
            'requests',
            'azure-storage-blob',
            'pandas',
        ],
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
        ],
        zip_safe=False,  # Required for conda build to work on Python 3.7.x.
    )
