#!/bin/bash

if [[ "$OSTYPE" == "linux-gnu" ]]; then
    # ...
    curl https://repo.continuum.io/miniconda/Miniconda3-latest-Linux-x86_64.sh > anaconda_install.sh
elif [[ "$OSTYPE" == "Darwin"* ]]; then
    # Mac OSX
    curl https://repo.continuum.io/miniconda/Miniconda3-latest-MacOSX-x86_64.sh > anaconda_install.sh
elif [[ "$OSTYPE" == "msys" ]]; then
    # Windows git bash
    curl https://repo.continuum.io/miniconda/Miniconda3-latest-Windows-x86_64.exe > anaconda_install.sh
else
       echo "OS unknown"
fi

chmod 777 anaconda_install.sh
./anaconda_install.sh
source activate base
pip install -r requirements.txt
