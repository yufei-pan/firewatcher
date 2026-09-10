from setuptools import setup
from firewatcher import version

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
            'firewatch=firewatcher:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: POSIX :: Linux',
        'Topic :: System :: Logging',
        'Topic :: System :: Monitoring',
    ],
    python_requires='>=3.6',
    license='GPLv3+',
)
