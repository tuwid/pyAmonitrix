from pyvirtualdisplay import Display
from selenium import webdriver


def site_check(site):
    browser = webdriver.Firefox()
    browser.get(site)
        
    #print browser.title
    navigationStart = browser.execute_script("return window.performance.timing.navigationStart")
    responseStart = browser.execute_script("return window.performance.timing.responseStart")
    domComplete = browser.execute_script("return window.performance.timing.domComplete")

    backendPerformance = responseStart - navigationStart
    frontendPerformance = domComplete - responseStart
 
    print "Back End: %s" % backendPerformance + "ms" +  " Front End: %s" % frontendPerformance + "ms " + " Total: " + str(backendPerformance + frontendPerformance) + "ms "
    browser.quit() 


display = Display(visible=0, size=(800, 600))
display.start()

site_check('http://pbx.webservice01.com/')
site_check('http://pbx.webservice01.com/')

display.stop()
