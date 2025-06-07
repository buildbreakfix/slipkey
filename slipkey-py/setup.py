from setuptools import setup, find_packages

setup(
    name='slipkey-sdk',
    version='0.1.0',
    author='AI Agent (for Slipkey)', # Replace with appropriate author
    author_email='no-reply@example.com', # Replace with appropriate email
    description='Python SDK for the Slipkey protocol.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='<URL to the repository if available, else leave blank or put placeholder>', # Replace with actual URL
    packages=find_packages(where='.'), # Correctly find packages within sdk-py
    install_requires=[
        'pyjwt>=2.0.0,<3.0.0',
        'cryptography>=3.0.0,<5.0.0',
        # Add other specific dependencies if any were implicitly added and not standard library
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License', # Assuming MIT
        'Operating System :: OS Independent',
        'Development Status :: 3 - Alpha', # Or Beta, Production/Stable as appropriate
    ],
    python_requires='>=3.7', # Based on example, adjust if necessary
)
