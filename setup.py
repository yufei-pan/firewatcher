import setuptools
from setuptools import setup
from firewatcher import version

classifiers = [
    'Programming Language :: Python :: 3',
    'Operating System :: POSIX :: Linux',
    'Topic :: System :: Logging',
    'Topic :: System :: Monitoring',
]
# setuptools 77+ (PEP 639) takes an SPDX license expression and warns about license classifiers (an error next to an
# expression); older ones (the newest for Python 3.8 and earlier, so all a Python 3.6 install has) know only the
# free-text license and the classifier. The LICENSE text reaches their sdist through MANIFEST.in.
if int(setuptools.__version__.split('.')[0]) >= 77:
    license_metadata = {'license_expression': 'GPL-3.0-or-later', 'license_files': ['LICENSE']}
else:
    license_metadata = {'license': 'GPL-3.0-or-later'}
    classifiers.append('License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)')

setup(
    name='firewatcher',
    version=version,
    description='Watch logs for incident patterns and persist surrounding context off-box',
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type='text/markdown',
    author='Yufei Pan',
    author_email='pan@zopyr.us',
    url='https://github.com/yufei-pan/firewatcher',
    py_modules=['firewatcher'],
    entry_points={
        'console_scripts': [
            'firewatcher=firewatcher:main',
        ],
    },
    classifiers=classifiers,
    python_requires='>=3.6',
    **license_metadata
)
