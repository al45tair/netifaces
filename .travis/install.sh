#!/bin/bash

if [[ $TRAVIS_OS_NAME == 'osx' ]]; then

    # On OS X, we use the "generic" language and manually install Python so
    # that we can specify the versions to test
    curl -L raw.githubusercontent.com/pyenv/pyenv-installer/master/bin/pyenv-installer | bash
    export PATH=~/.pyenv/bin:$PATH
    eval "$(pyenv init -)"
    pyenv install --skip-existing $PYTHON_VERSION
    pyenv global $PYTHON_VERSION
    pyenv shell $PYTHON_VERSION
    pip install -U pip setuptools wheel py

fi

pip install .
