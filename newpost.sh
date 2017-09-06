#!/bin/bash

echoinfo="Usages: ./newpost [-n post_name] [-N post_title] [-l layout] [-t tags]\
 [-d description] [-c comment_opt] [-f format_end] [-h] \n\
 n, N: n must in english while N could be in chinese \n\
 l: layout options are spotpost \n\
 t: format of tags must be \"tag1 tag2 ...\" \n\
 c: disqus, intensedebate, duoshuo \n\
 f: the format of post source file, default is .md, others: html \n\
 h: this help. \n"

post_srcname="New Post"
post_title=""
layout="spotpost"
tags=""
desc=""
comment_opt=""
format_end="md"

while getopts n:N:l:t:d:c:f:h opt
do
        case "$opt" in
                n)  # post source name
                        post_srcname="$OPTARG"
                        ;;

                N)  # post title
                        post_title="$OPTARG"
                        ;;

                l)  # layout
                        layout="$OPTARG"
                        ;;

                t)  # tags
                        tags="$OPTARG"
                        ;;

                d)  # description
                        desc="$OPTARG"
                        ;;

                c)  # comments
                        comment_opt="$OPTARG"
                        ;;

                f)  # comments
                        format_end="$OPTARG"
                        ;;

                h)  # help
                        echo -e $echoinfo
                        exit 1
                        ;;

        esac
done

#echo $1
#echo $2
#echo $#

#post_name=`date  "+%Y-%m-%d"`-`echo $post_srcname | sed "s/[ \/ : ^ \& \% \# \! , . { } ( ) * ? \" < > |]/-/g"`.$format_end
post_name=2000-01-01-`echo $post_srcname | sed "s/[ \/ : ^ \& \% \# \! , . { } ( ) * ? \" < > |]/-/g"`.$format_end
#echo $post_name

post_name=`echo $post_name | sed 's/'"'"/-'/g'`
post_name=`echo $post_name | sed 's/-*-/-/g'`
post_name=`echo $post_name | sed 's/-\./\./g'`
#echo $post_name

file=./${post_name}
touch $file
# Write the head of title
echo --- > $file
echo layout: $layout >> $file
if [ -n "$post_title" ]; then
        echo title: \"$post_title\" >> $file
else
        echo title: \"$post_srcname\" >> $file
fi
echo date: `date "+%Y-%m-%d %H:%M:%S"` +0800  >> $file


if [ -n "$tags" ]; then
        echo tags: $tags >> $file
fi

if [ -n "$desc" ]; then
        echo description: $desc >> $file
fi

if [ -n "$comment_opt" ]; then
        if [ "$comment_opt" = "intensedebate" ]; then
                echo intensedebate: true >> $file
        elif [ "$comment_opt" = "disqus" ]; then
                echo disqus: true >> $file
        elif [ "$comment_opt" = "duoshuo" ]; then
                echo duoshuo: true >> $file
        fi
fi

echo --- >> $file

echo Successfully create $file

vim $file
