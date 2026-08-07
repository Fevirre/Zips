MKT ScriptableCourse Runtime Dumper
===================================

This captures the live IL2CPP ScriptableCourse object after Unity has
deserialized it. It produces Unity JsonUtility output plus a recursive
reflection dump and field layout.

Install:
  py -m pip install frida==17.17.0

Connect:
  adb forward tcp:27042 tcp:27042

Launch the patched MKT build, then run:
  py capture_scriptable_course.py

Navigate to a fully downloaded course and follow the prompts. Arm the capture
immediately before tapping Practice. Wait until the race is fully loaded before
forcing the final scan.

Results are written to:
  ScriptableCourse-dump

If no class is found, send the complete terminal output. The next fallback is
to dump runtime class names containing "Course" and identify MKT's renamed
ScriptableCourse type.
