---
layout: post
title: "Django Configuration"
date: 2015-11-06 16:25:06
description: What the fuck...
tags: UNIX OS
share: true
intensedebate: true
---

## Django Configuration

#### Create Project and Init

- `~# django-admin startproject sitename`
- `~# cd sitename`
- `~/sitename# python3 manage.py startapp appname`
- `~/sitename# python3 manage.py migrate` 创建数据库。注意，1.9之前的版本是`python3 manage.py syncdb`，今改了
- `~/sitename# python3 manage.py createsuperuser` 创建超级用户，用来登录控制台
- `~/sitename# python3 manage.py runserver 0.0.0.0:9876` 运行服务，可以在外面访问，但是要开放相应防火墙端口

#### DjangoUeditor
- `pip install DjangoUeditor` 这个存在问题，后来发现是因为DjangoUeditor基于python 2.7，不支持python3，改用DjangoUeditor3即可
以下是DjangoUeditor3做法：
-

#### Markdown support

- `MarkupField`
- `# zypper install python-pygments`
- `pygmentize -S default -f html -a .codehilite > code.css`
