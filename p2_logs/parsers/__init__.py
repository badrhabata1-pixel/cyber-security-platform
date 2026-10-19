from .ssh import parse_ssh
from .nginx import parse_nginx
from .platform import parse_platform

PARSERS = {"ssh": parse_ssh, "web": parse_nginx, "platform_login": parse_platform}
