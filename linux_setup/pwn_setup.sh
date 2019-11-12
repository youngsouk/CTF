echo "export LC_CTYPE=C.UTF-8" >> ~/.zshrc

sudo apt-get install python python-pip git curl wget vim zsh gdb python3 python3-pip cmake time -y
sudo pip3 install unicorn
sudo pip3 install keystone-engine
sudo pip3 install capstone
sudo pip3 install ropper

sudo pip install pwntools

sudo apt-get install ruby-full -y
sudo gem install one_gadget
sudo gem install seccomp-tools

wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py
echo "source ~/.gdbinit-gef.py" >> ~/.gdbinit