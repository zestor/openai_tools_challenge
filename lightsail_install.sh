sudo python3 -m ensurepip --upgrade
sudo python3 -m pip install --upgrade pip
sudo dnf install git-all -y
sudo dnf install python3-virtualenv -y
git clone https://github.com/zestor/openai_tools_challenge.git
cd ~/openai_tools_challenge
sudo python3 -m venv virtual_env
source virtual_env/bin/activate
pip install -r requirements.txt
deactivate
sudo cp openai_tools_challenge.service /etc/systemd/system/openai_tools_challenge.service
sudo systemctl start openai_tools_challenge
sudo systemctl enable openai_tools_challenge
sudo systemctl status openai_tools_challenge