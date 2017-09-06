---
layout: post
title: "filename characters"
date: 2016-11-06 16:25:06
description: What the fuck...
tags: UNIX OS
share: true
intensedebate: true
---

```
Windows denied (9): \ / : * ? \" < > |
```

### Windows
#### Quoting

Quoting is used to remove the special meaning of certain characters or words to the shell. Quoting can be used to preserve the literal meaning of the special characters in the next paragraph; prevent reserved words from being recognised as such; and prevent parameter expansion and command substitution within here-document processing (see Here-document ).

The following characters must be quoted if they are to represent themselves:

>|  &  ;  <  >  (  )  $  `  \  "  '     

and the following may need to be quoted under certain circumstances. That is, these characters may be special depending on conditions described elsewhere in this specification:

>\*  ?  [  #  ~  =  %
