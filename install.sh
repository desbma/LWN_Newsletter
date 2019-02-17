#!/bin/bash -e

# package dependencies
apt-get install -yV --no-install-recommends python3-requests python3-appdirs python3-lxml python3-cssselect

# main script
install -v -Dm 755 -t /usr/local/bin ./lwn.py

# user
install -v -Dm 644 -t /etc/sysusers.d ./systemd/lwn.conf
systemd-sysusers

# systemd units
install -v -Dm 644 -t /etc/systemd/system ./systemd/lwn.{service,timer}

# dirs
mkdir -pv /var/lib/lwn/.{cache,config}/lwn

# python venv
python3 -m venv --system-site-packages /var/lib/lwn/pyvenv
/var/lib/lwn/pyvenv/bin/pip install -r requirements.txt

# initial dummy config
if [ ! -f /var/lib/lwn/.config/lwn/netrc ]
then
  echo 'machine lwn.net
login LWN_LOGIN
password LWN_PASSWORD

machine smtp.gmail.com
login GMAIL_LOGIN
password GMAIL_PASSWORD' > /var/lib/lwn/.config/lwn/netrc
fi
if [ ! -f /var/lib/lwn/.config/lwn/config.json ]
then
  echo '{
  "recipients": [],
  "reply_to": "John Doe<johndoe@example.com>",
  "subject": "LWN Custom Newsletter"
}
' > /var/lib/lwn/.config/lwn/config.json
fi

# permissions
chown -Rc lwn:lwn /var/lib/lwn/.cache/lwn
chmod -c 640 /var/lib/lwn/.config/lwn/*
chown -Rc root:lwn /var/lib/lwn/.config/lwn/*


echo '
Edit configuration in /var/lib/lwn/.config/lwn/config.json and credentials in /var/lib/lwn/.config/lwn/netrc
Enable daily newsletter with: systemctl enable --now lwn.timer'
