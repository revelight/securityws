
import re
from proxy_ml_email_code_classifier import *
import urllib.request
from html.parser import HTMLParser
from proxy_prints import *


def classify_text_w_html_support(text):

    print(SECTAG + 'classify text with html support:')

    # report excerpt
    exlen = 20
    if len(text) > exlen:
        print(SUBTAG2+'content excerpt: {} ........ {}'.format(text[:exlen], text[-exlen:]))
    else:
        print(SUBTAG2+'content excerpt: {}'.format(text))

    # if text is html - scrape it
    scrape_html = h_is_html(text)

    if scrape_html:
        print(' --> classify as html with scraping')
        return h_scrape_html_and_classify(text)
    else:
        print(' --> classify as raw text (not html)')
        return email_code_ML_classifier(text)


#
#
#                   helpers
# -----------------------------------------------


html_regex = '\s*<!doctype\s+html'
def h_is_html(text):
    # naively check header - <!DOCTYPE html>
    # non-legal html can be classifed raw,
    # and are hence more likely to be classsidied as CODE
    match = re.match(html_regex, text, re.IGNORECASE)
    if match is not None:
        print(SUBTAG2+'html doctype found.. ', end='')
        return True
    print(SUBTAG2+'html doctype not found.. ', end='')
    return False


def h_get_uri_as_str(uri):
    f = urllib.request.urlopen(uri)
    page = f.read().decode()
    print('=========================== uri page read is: ================================= \n{}\n============================= end of uri page read =================================='.format(page))
    return page


def h_scrape_html_and_classify(page):

    class MyHTMLParser(HTMLParser):

        datalist = []
        tags_summary = set()
        collected_tag_summary = set()
        collectTag = 1
        printBreakdown = 0
        tag_blacklist = {'script', 'style'}
        tag_whitelist = {'title', 'code', }

        def handle_starttag(self, tag, attrs):
            if self.printBreakdown:
                print("----------------- tag START :", tag)
            self.tags_summary.add(tag)
            if tag in self.tag_blacklist:
                self.collectTag = 0
            elif tag in self.tag_whitelist:
                self.collectTag = 1
            else:
                self.collectTag = 1

            if self.collectTag:
                self.collected_tag_summary.add(tag)

        def handle_endtag(self, tag):
            if self.printBreakdown:
                print("------------------- tag END :", tag, '\n')

        def handle_data(self, data):
            if self.printBreakdown:
                print("data:", data)
            if self.collectTag:
                self.datalist.append(data)


    parser = MyHTMLParser()
    parser.feed(page)

    print('\n\n')
    text_str = ''.join(parser.datalist)
    text_str = re.sub('\n\s*\n', '\n', text_str)
    print('============================= scrapped text is: ================================= \n{}\n============================= end of scraped text =================================='.format(text_str))
    print('\n------------------- REPORT -----------------------')
    print('All HTML Tags summary:\n{}'.format(parser.tags_summary))
    print('Collected HTML Tags summary:\n{}'.format(parser.collected_tag_summary))
    ml_class = email_code_ML_classifier(text_str)
    print('----------------------------------------------------')
    print('\n\n')

    return ml_class


from proxy_html_helpers_samples import *
def h_proxy_html_helpers_tests():
    h_scrape_html_and_classify(h_get_uri_as_str(u2))
    classify_text_w_html_support(text1)

#h_proxy_html_helpers_tests()

