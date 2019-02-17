LWN Newsletter
==============

Tool to send daily (week days) emails containing summary of news from the [LWN website](https://lwn.net/).

This requires a paid account, because links to non-free articles are converted to "subscriber links" (usable without a paid account).

**Use this to promote LWN, not to rip them off :)**

If you send emails to many people who appreciate LWN content, it may be a good idea to buy a group subscription.


## Installation

Requirements: Python >= 3.6 and a Linux distribution with Systemd.

Run `./install.sh` as root in the source tree.

Follow instructions to configure, add your credentials (LWN account, and Gmail account used to send the emails), and enable automatic emails.

You may also need to enable ["insecure" login](https://support.google.com/accounts/answer/6010255) for you Gmail account, because by default Google blocks SMTP connections from unknown apps.


## License

[GPLv3](https://www.gnu.org/licenses/gpl-3.0-standalone.html)