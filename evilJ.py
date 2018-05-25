#!/usr/bin/env python

# evilJ v0.1
# Find common vulnerabilities in browser's extensions
# Follow (Medium / Twitter): @localh0t

# XSS/Execute JavaScript:
# =======================

# eval(string)              If the argument is an expression, eval() evaluates the expression. If the argument is one or more JavaScript statements, eval() executes the statements.
# setInterval(code, every)  Executes "code", over and over again, at specified "every" time intervals.
# setTimeout(code, timeout) Executes "code", once, after waiting a specified number of milliseconds ("timeout").
# .innerHTML                The innerHTML property sets or returns the HTML content (inner HTML) of an element.
# executeScript             The ExecuteScript(String, Object[]) method executes JavaScript in the context of the currently selected frame or window.


# XSS/Execute JavaScript (jQuery):
# ================================

# By design, any jQuery constructor or method that accepts an HTML string - jQuery(), .append(), .after(), etc. - can potentially execute code.
# This can occur by injection of script tags or use of HTML attributes that execute code (for example, <img onload="">).
# Do not use these methods to insert strings obtained from untrusted sources such as URL query parameters, cookies, or form inputs.
# Doing so can introduce cross-site-scripting (XSS) vulnerabilities. Remove or escape any user input before adding content to the document.
# https://api.jquery.com

# .html()                           Get the HTML contents of the first element in the set of matched elements.
# .append( content [, content ] )   Insert content, specified by the parameter, to the end of each element in the set of matched elements.
# .after( content [, content ] )    Insert content, specified by the parameter, after each element in the set of matched elements.
# jQuery( selector [, context ] )   Accepts a string containing a CSS selector which is then used to match a set of elements.

# Unsafe Requests:
# ================

# http://                                                   Search for a possible non-secure connection to some site.
# window.open(URL, name, specs, replace)                    The open() method opens a new browser window.
# window.openDialog(url, name, features, arg1, arg2, ...)   window.openDialog() is an extension to window.open().
# window.showModalDialog(uri[, arguments][, options])       The window.showModalDialog() creates and displays a modal dialog box containing a specified HTML document.
# nsIWindowWatcher.openWindow()                             Creates a new window.
# XMLHttpRequest                                            The XMLHttpRequest object is used to exchange data with a server behind the scenes.

import os
import sys

extensions = [".js"]

execJavaScript = ["eval(", "setInterval(", "setTimeout(", ".innerHTML", "executeScript("]
execjQuery = [".html()", ".append(", ".after(", "jQuery("]
unsafeReq = ["http://", "window.open(", "window.openDialog(", "window.showModalDialog(", "openWindow(", "XMLHttpRequest"]

def scanCode(rootDir, unsafe, vulnType):
    print "\n##########################################################################################"
    print "\n[!] Testing type: " + str(vulnType) + "\n"
    for dirName, subdirList, fileList in os.walk(rootDir, topdown=False):
        for fname in fileList:
            if any(ext in fname for ext in extensions):
                fullPath = dirName + "/" + fname
                numberLines = 1
                for line in open(fullPath):
                    for possibleUnsafe in unsafe:
                        if possibleUnsafe.lower() in line.lower():
                            print "\n[+] FULL PATH    : " + str(fullPath)
                            print "[+] TYPE         : " + str(possibleUnsafe)
                            print "[+] LINE NUMBER  : " + str(numberLines)
                            print "[+] LINE MATCHED : " + str(line)
                            print "\n##########################################################################################"
                    numberLines += 1

def showHelp():
    print "\n#################################"
    print "# [!] Usage: " + str(os.path.basename(__file__)) + " [BASE DIR] #"
    print "# [!] Exiting ...               #"
    print "#################################\n"
    exit(0)

if len(sys.argv) != 2:
    showHelp()
    sys.exit(0)


print "\n[!] Starting...\n"

scanCode(sys.argv[1], execJavaScript, "XSS/Execute JavaScript")
scanCode(sys.argv[1], execjQuery, "XSS/Execute JavaScript (jQuery)")
scanCode(sys.argv[1], unsafeReq, "Unsafe Requests")


print "\n[!] Finished !\n"
sys.exit(0)
