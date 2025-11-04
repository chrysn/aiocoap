.. meta::
  :copyright: SPDX-FileCopyrightText: Christian Amsüss
  :copyright: SPDX-License-Identifier: MIT

Files in here prepare ``../aiocoap-kivy-widget`` to be run on Android:

* ``./prepare-launcher-code.py``

  To run it this way, install the `Kivy Launcher`_ on the Android device,
  run ``./prepare-launcher-code.py`` in the git checkout.
  This creates several files in ``./for-launcher``;
  copy these files and directories from ``for-launcher`` into ``/storage/emulated/0/kivy/aiocoap-kivy-widget/`` on the Android device.

  Then, the demo is available through the Kivy Launcher.

  This is easy to run and takes no relevant resources,
  but can not easily contain advanced dependencies such as the cryptography package.

* ``./build-with-buildozer.py``

  To run it this way, run ``./build-with-buildozer.py android debug deploy run``
  (or use any other arguments -- they will all be forwarded to buildozer_;
  ``debug`` will build the ``.apk``,
  and ``deploy run`` will install and launch it on an ADB connected Android device).

  This copies together all relevant files into ``./for-buildozer``,
  installs buildozer in a virtualenv in ``./venv-buildozer``,
  and runs buildozer.

  Note that buildozer may download significant amounts of SDKs and NDKs with questionable licenses,
  and possibly stores some of that in cache directories outside of this directory.

.. _`Kivy launcher`: https://github.com/kivy/kivy-launcher
.. _buildozer: https://buildozer.readthedocs.io/en/latest/quickstart.html
