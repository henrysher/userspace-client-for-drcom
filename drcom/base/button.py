#!/usr/bin/python

# ZetCode PyGTK tutorial 
#
# This example shows four buttons
# in various modes 
#
# author: jan bodnar
# website: zetcode.com 
# last edited: February 2009


import gtk

class PyApp(gtk.Window):
    def __init__(self):
        super(PyApp, self).__init__()
        
        self.set_title("Buttons")
        self.set_size_request(250, 200)
        self.set_position(gtk.WIN_POS_CENTER)
        
        self.btn1 = gtk.Button("Button")
        self.btn1.set_sensitive(False)
        btn2 = gtk.Button("Button")
        btn2.connect('clicked', self.button_ON)
        btn3 = gtk.Button(stock=gtk.STOCK_CLOSE)
        btn4 = gtk.Button("Button")
        btn4.set_size_request(80, 40)

        fixed = gtk.Fixed()

        fixed.put(self.btn1, 20, 30)
        fixed.put(btn2, 100, 30)
        fixed.put(btn3, 20, 80)
        fixed.put(btn4, 100, 80)
        
        self.connect("destroy", gtk.main_quit)
        
        self.add(fixed)
        self.show_all()

    def button_ON(self, widget):
        self.btn1.set_sensitive(True)

PyApp()
gtk.main()

