MKT Course Capture (non-root, Frida Gadget 17.17.0)
====================================================

Files required in this folder (or keep mkt-signature-spoof.js one directory up):
  capture_mkt_course.py
  mkt-course-capture.js
  mkt-signature-spoof.js

Install the matching Frida Python package:
  py -m pip install frida==17.17.0

Connect the phone and forward Gadget:
  adb forward tcp:27042 tcp:27042

Launch the patched MKT build, then run:
  py capture_mkt_course.py

Navigate to a fully downloaded course. Press Enter in the capture tool
immediately before tapping Practice, tap Practice, and wait for the race to
finish loading. Press Enter again to stop the capture.

Captured paths and files are written under mkt-course-dump. If the first run
does not reveal an obvious CourseData/CourseMap file, repeat with Paris
Promenade and send the terminal log plus the generated file listing.
