#!/usr/bin/env python3

""" Send custom LWN newsletter. """

import argparse
import collections
import datetime
import email.mime.text
import inspect
import json
import logging
import netrc
import os
import pickle
import shelve
import smtplib
import ssl
import urllib.parse
import xml.etree.ElementTree

import appdirs
import lxml.etree
import lxml.cssselect
import requests


Article = collections.namedtuple("Article",
                                 ("id",
                                  "title",
                                  "date",
                                  "author",
                                  "description",
                                  "url",
                                  "free"))


BASE_URL = "https://lwn.net"
RSS_URL = f"{BASE_URL}/headlines/newrss"
LOGIN_URL = f"{BASE_URL}/Login/"
MAKE_LINK_URL = f"{BASE_URL}/SubscriberLink/MakeLink/"
GMAIL_SMTP_HOSTNAME = "smtp.gmail.com"

HTML_PARSER = lxml.etree.HTMLParser()
SUBSCRIBER_LINK_SELECTOR = lxml.cssselect.CSSSelector(".ArticleText a")
TITLE_EXCLUDES_PREFIXES = ("LWN.net Weekly Edition",
                           "Security updates for ")

APP_NAME = os.path.splitext(os.path.basename(inspect.getfile(inspect.currentframe())))[0]
CONFIG_DIR = appdirs.user_config_dir(APP_NAME)
CACHE_DIR = appdirs.user_cache_dir(APP_NAME)


def get_rss_feed():
  """ Fetch LWN RSS feed. """
  logging.getLogger().info(f"GET {RSS_URL}")
  response = requests.get(RSS_URL)
  response.raise_for_status()
  response.encoding = "utf-8"
  return response.text


def parse_rss_feed(xml_data):
  """ Parse RSS feed and yield Article tuples. """
  xml_ns_prefix = "{http://purl.org/rss/1.0/}"
  xml_root = xml.etree.ElementTree.fromstring(xml_data)
  for xml_item in xml_root.iterfind(f"./{xml_ns_prefix}item"):
    url = xml_item.find(f"./{xml_ns_prefix}link").text
    if url.endswith("rss"):
      url = url[:-3]
    title = xml_item.find(f"./{xml_ns_prefix}title").text
    if title.startswith("[$] "):
      title = title[4:]
      free = False
    else:
      free = True
    article_id = int(url.rsplit("/", 2)[-2])
    xml_ns_prefix2 = "{http://purl.org/dc/elements/1.1/}"
    date = xml_item.find(f"./{xml_ns_prefix2}date").text
    date = datetime.datetime.strptime(date, "%Y-%m-%dT%H:%M:%S+00:00")
    author = xml_item.find(f"./{xml_ns_prefix2}creator").text
    desc = xml_item.find(f"./{xml_ns_prefix}description").text.strip()
    yield Article(article_id,
                  title,
                  date,
                  author,
                  desc,
                  url,
                  free)


def login():
  """ Login to LWN.net and return session or None if it failed. """
  session = requests.Session()
  creds = netrc.netrc(os.path.join(CONFIG_DIR, "netrc"))
  lwn_host = urllib.parse.urlsplit(BASE_URL).netloc
  login, _, password = creds.hosts[lwn_host]
  post_params = {"Username": login,
                 "Password": password}
  logging.getLogger().info(f"POST {LOGIN_URL}")
  response = session.post(LOGIN_URL, data=post_params)
  response.raise_for_status()
  if len(response.history) == 2:
    return session


def make_free_link(session, article_id, cache_filepath):
  """ Generate a free link for an article. """
  with shelve.open(cache_filepath, "c") as cache:
    try:
      url = cache[str(article_id)]
    except KeyError:
      if session is None:
        # login
        session = login()
        if session is None:
          logging.getLogger().error("Login failed")
          exit(1)
      post_params = {"articleid": str(article_id)}
      logging.getLogger().info(f"POST {MAKE_LINK_URL}")
      response = session.post(MAKE_LINK_URL, data=post_params)
      response.raise_for_status()
      page = lxml.etree.XML(response.text, HTML_PARSER)
      links = tuple(filter(lambda x: x.startswith(f"{BASE_URL}/SubscriberLink/{article_id}/"),
                           (l.get("href") for l in SUBSCRIBER_LINK_SELECTOR(page))))
      assert(len(links) == 1)
      url = links[0]
      cache[str(article_id)] = url
  return session, url


def format_email(articles, *, base_title, number, addr_reply, addr_to):
  """ Format HTML email. """
  # html
  html = ["<html><head><style>",
          "body {font-family:sans-serif}",
          "p {margin-top:1em; margin-bottom:1em}",
          ".small {font-size:80%}",
          "</style></head><body>",
          "Recent articles:<ul>"]
  for article in articles:
    html.append(f"<li><p><a href=\"{article.url}\">{'' if article.free else '<strong>'}{article.title}{'' if article.free else '</strong>'}</a> by {article.author} {article.date.strftime('%Y-%m-%d %H:%M')}<br>")
    desc = article.description.replace("<p>", "").replace("</p>", "").strip()
    html.append(f"{desc}</p></li>")
  html.append("</ul>")
  html.append(f"<br><p class=\"small\">This email has been <a href=\"https://github.com/desbma/LWN_Newsletter\" title=\"Source code used to generate this email\">automatically generated</a>. If you wish to unsubscribe, contact <a href=\"mailto:{addr_reply}?subject=Unsubscribe from {base_title}\">{addr_reply}</a>.<br>"
              "Links in <strong>bold</strong> are LWN subscriber-only content, and have been generated using a paid account. Do NOT send, publish or share them beyond the recipients of theses emails.<br></p>")
  html = "\n".join(html)

  # build email
  msg = email.mime.text.MIMEText(html, "html")
  msg["Subject"] = f"{base_title} #{number}"
  msg["From"] = addr_reply
  msg["Reply-To"] = addr_reply
  msg["To"] = addr_to

  return msg


def get_gmail_client_ssl_context():
  """ Setup a sane client SSL context and return it.

  This requires Python >= 3.6. """
  ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
  try:
    ssl_context.minimum_version = ssl_context.maximum_version = ssl.TLSVersion.TLSv1_2
  except AttributeError:
    # Python < 3.7
    ssl_context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1)
  ssl_context.load_default_certs()
  ssl_context.verify_mode = ssl.CERT_REQUIRED
  ssl_context.verify_flags = ssl.VERIFY_X509_STRICT
  ssl_context.check_hostname = True
  ssl_context.options |= ssl.OP_NO_COMPRESSION
  # https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
  ssl_context.set_ciphers(":".join(("ECDHE-ECDSA-AES256-GCM-SHA384",
                                    "ECDHE-RSA-AES256-GCM-SHA384",
                                    "ECDHE-ECDSA-CHACHA20-POLY1305",
                                    "ECDHE-RSA-CHACHA20-POLY1305",
                                    "ECDHE-ECDSA-AES128-GCM-SHA256",
                                    "ECDHE-RSA-AES128-GCM-SHA256",
                                    "ECDHE-ECDSA-AES256-SHA384",
                                    "ECDHE-RSA-AES256-SHA384",
                                    "ECDHE-ECDSA-AES128-SHA256",
                                    "ECDHE-RSA-AES128-SHA256")))
  return ssl_context


def send_emails_from_gmail(messages):
  """ Send several emails in one shot using gmail account. """
  creds = netrc.netrc(os.path.join(CONFIG_DIR, "netrc"))
  gmail_login, _, gmail_password = creds.hosts[GMAIL_SMTP_HOSTNAME]
  with smtplib.SMTP_SSL(GMAIL_SMTP_HOSTNAME, context=get_gmail_client_ssl_context()) as smtp_session:
    rc = smtp_session.login(gmail_login, gmail_password)[0]
    if rc != 235:
      raise ValueError(rc)
    for message in messages:
      logging.getLogger().info(f"...to {message['To']}")
      smtp_session.send_message(message)


if __name__ == "__main__":
  # parse args
  arg_parser = argparse.ArgumentParser(description=__doc__,
                                       formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  arg_parser.add_argument("-v",
                          "--verbosity",
                          choices=("warning", "normal", "debug"),
                          default="normal",
                          dest="verbosity",
                          help="Level of output to display")
  args = arg_parser.parse_args()

  # setup logger
  logging_level = {"warning": logging.WARNING,
                   "normal": logging.INFO,
                   "debug": logging.DEBUG}
  logging.basicConfig(level=logging_level[args.verbosity],
                      format="%(message)s")
  for noisy_logger in ("requests", "urllib3", "chardet"):
    logging.getLogger(noisy_logger).setLevel(logging.WARNING)

  # setup caches
  os.makedirs(CACHE_DIR, exist_ok=True)
  sl_cache_filepath = os.path.join(CACHE_DIR, "subscriber_links.db")
  sent_cache_filepath = os.path.join(CACHE_DIR, "sent.db")
  count_filepath = os.path.join(CACHE_DIR, "count.dat")

  # read count
  try:
    with open(count_filepath, "rb") as f:
      newsletter_count = pickle.load(f)
  except FileNotFoundError:
    newsletter_count = 0

  # read config
  config_filepath = os.path.join(CONFIG_DIR, "config.json")
  with open(config_filepath, "rt") as f:
    config = json.load(f)

  # get main RSS feed
  xml_data = get_rss_feed()

  # parse RSS feed
  with shelve.open(sent_cache_filepath, "c") as sent_articles:
    session = None
    articles_to_send = []
    for article in parse_rss_feed(xml_data):
      if any(map(article.title.startswith, TITLE_EXCLUDES_PREFIXES)):
        logging.getLogger().info(f"Excluding article '{article.title}' because of blacklisted prefix")
        continue
      if str(article.id) in sent_articles:
        continue
      logging.getLogger().info(f"New article: '{article.title}' ({article.url}) {'' if article.free else 'non '}free")
      if not article.free:
        session, free_url = make_free_link(session, article.id, sl_cache_filepath)
        logging.getLogger().info(f"Subscriber link: {free_url}")
        article = Article(*(article[:-2] + (free_url, article[-1])))
      articles_to_send.append(article)
    articles_to_send.reverse()

    if articles_to_send:
      # update count
      newsletter_count += 1

      messages = []
      for addr_to in config["recipients"]:
        # format email
        logging.getLogger().info(f"Formatting email to send to {addr_to}")
        message = format_email(articles_to_send,
                               base_title=config["subject"],
                               number=newsletter_count,
                               addr_reply=config["reply_to"],
                               addr_to=addr_to)
        messages.append(message)

      # sent them
      logging.getLogger().info(f"Sending emails...")
      send_emails_from_gmail(messages)

      # mark articles as sent
      for article in articles_to_send:
        sent_articles[str(article.id)] = True

      # save count
      with open(count_filepath, "wb") as f:
        pickle.dump(newsletter_count, f, pickle.HIGHEST_PROTOCOL)

    else:
      logging.getLogger().info("Nothing new to send")
