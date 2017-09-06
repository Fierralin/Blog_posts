---
layout: post
title: "DRL Survey"
date: 2017-09-06 16:25:06
description: DRL
tags: UNIX OS DRL
---

#### Trend 1: Main Challenges in Deep Reinforcement Learning

###### Unappropriate approximation function.

- Small network may fail to approximate Q function.
- Large network can lead to overfitting.

@ Existing works focused on carefully tuning of the network size and hyperparameters can help.

###### Trend 2: Moving target.

- Learning moves with training batch.
- The target changes result in oscillation and divergence of the network.

@ Existing works [1] proposed the regular updating method with the aim to fix the target value.

###### Trend 3: Maximization bias.

- The network may overestimate the Q function.
- This leads to the poor performance.

@ Double Q Learning [2] can help.

###### Trend 4:

###### Biased data in memory
