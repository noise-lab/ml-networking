#!/bin/bash
curl https://repo.continuum.io/miniconda/Miniconda3-latest-MacOSX-x86_64.sh > anaconda_install.sh
chmod 777 anaconda_install.sh
./anaconda_install.sh
source activate base
pip install -r requirements.txt
