
from tkinter import *

class Interface(Frame):
  def __init__(self, master=None):
    super().__init__(master)
    self.master = master
    self.pack()
    self.create_widgets()
 
  def create_widgets(self):
    # Add here widgets
    self.hi_there = Button(self, text="Hello World\n(click me)", fg="blue",
                              command=self.say_hi)
    self.hi_there.pack(side="top")
    self.quit = Button(self, text="QUIT", fg="red", command=self.master.destroy)
    self.quit.pack(side="bottom")
  
  # Implement functionalities
  def say_hi(self):
    print("hi there, everyone!")