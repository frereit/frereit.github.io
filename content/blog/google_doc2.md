---
author: "frereit"
title: "Using Google Docs as a C2 proxy with a headless browser"
date: "2024-11-07"
description: "In this article we show how to use any Chromium-based browser as a C2 agent and Google Docs as a C2 proxy."
tags:
    - "red-teaming"
    - "tooling"
toc: false
---

## Abstract

> When building your C2 agent, you may want to avoid outbound traffic directly from your agent to the C2 server for a number of reasons. You may have strict firewall rules that block all non-browsers from accessing the Internet, or you may want to bypass a proxy that only allows access to certain trusted websites. By spawning a headless browser process and using the Chrome DevTools Protocol to interact with a website, you can use the browser’s network stack to send and receive data, effectively bypassing any firewall or web proxy. In this article we show how to use any Chromium-based browser as a C2 agent and Google Docs as a C2 proxy and how to detect this. We provide sample code in Rust and a basic agent and server that can be used to execute shell commands on the agent and receive the output of the commands.

## Full Article

This article by me was published at cirosec's blog:

**<https://cirosec.de/en/news/google-doc2>**

<!-- https://web.archive.org/web/20241108095351/https://cirosec.de/en/news/google-doc2/ -->
