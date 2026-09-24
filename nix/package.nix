{
  lib,
  stdenv,
  python3,
  fetchPypi,
  fetchurl,
  makeWrapper,
  autoPatchelfHook,
  src, # the flake root, passed in from flake.nix (self)
}:

let
  python3Packages = python3.pkgs;

  # not in nixpkgs (lnbits' BOLT11 codec) - pinned to the same version and
  # hash as uv.lock. Its upstream `requires-python = ">=3.10,<3.13"` cap is
  # conservative (the library runs fine on 3.13/3.14 - this repo's whole
  # test suite passes against it), so it's relaxed here rather than
  # failing nixpkgs' interpreter-version check.
  bolt11 = python3Packages.buildPythonPackage rec {
    pname = "bolt11";
    version = "2.2.0";
    pyproject = true;

    src = fetchPypi {
      inherit pname version;
      hash = "sha256-Es2dDT6w8IxQWxg08hYwNpl0wd47nDm5q9SN3Q0aREs=";
    };

    postPatch = ''
      sed -i 's/>=3.10,<3.13/>=3.10/' pyproject.toml
    '';

    build-system = [ python3Packages.hatchling ];

    dependencies = with python3Packages; [
      click
      base58
      coincurve
      bech32
      bitstring
    ];

    # upstream tests want pytest-cov and friends; skipped - this repo's own
    # suite exercises bolt11 thoroughly (every fake invoice is one)
    doCheck = false;

    meta = {
      description = "A library for encoding and decoding BOLT11 payment requests";
      homepage = "https://github.com/lnbits/bolt11";
      license = lib.licenses.mit;
    };
  };

  # not in nixpkgs and not buildable by nix's sandbox (it links Bitcoin
  # Core's own script interpreter, compiled from a vendored source tree via
  # CMake/Boost - see ~/repos/lnurlcashkernel). It ships as a prebuilt,
  # per-arch manylinux wheel (pure ctypes: one `.so` loaded at import time,
  # no CPython C-API surface), so this fetches that wheel straight from
  # PyPI instead of trying to rebuild the interpreter from source - same
  # sha256 as uv.lock. autoPatchelfHook rewires the `.so`'s dynamic loader
  # from the manylinux image's glibc to nixpkgs' (it links only
  # libstdc++/libm/libgcc_s/libpthread/libc - no libpython, so no wrapping
  # needed beyond that).
  lnurlcashKernelWheels = {
    x86_64-linux = {
      url = "https://files.pythonhosted.org/packages/ab/f1/a265669f3dcf6b7cc93f76f25b1df2f71431d26a91d24b874931561a83b7/lnurlcash_kernel-0.1.0-py3-none-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl";
      # sha256, same as uv.lock (hex, not SRI, to avoid a lossy base64 transcription)
      sha256 = "b01f5142af4081fa5b1ea649800e6c8f718b5d944dfb36f7398c69ac6804e351";
    };
    aarch64-linux = {
      url = "https://files.pythonhosted.org/packages/08/88/77ee8b229ec7a39487f6690c91120d539e7b79e930c2ee5a4fd77f5add77/lnurlcash_kernel-0.1.0-py3-none-manylinux_2_27_aarch64.manylinux_2_28_aarch64.whl";
      sha256 = "cbfcdca96d2a71b8d872d063b571f94d876fc8f375cef6d87b911da805377dbf";
    };
  };

  lnurlcashKernel =
    let
      wheel =
        lnurlcashKernelWheels.${stdenv.hostPlatform.system}
          or (throw "lnurlcash-kernel: no prebuilt wheel for ${stdenv.hostPlatform.system}");
    in
    python3Packages.buildPythonPackage {
      pname = "lnurlcash-kernel";
      version = "0.1.0";
      format = "wheel";

      src = fetchurl { inherit (wheel) url sha256; };

      nativeBuildInputs = [ autoPatchelfHook ];
      buildInputs = [ stdenv.cc.cc.lib ];

      pythonImportsCheck = [ "lnurlcashkernel" ];

      meta = {
        description = "Verify LUD-25 note (taproot key- and script-path) spends with Bitcoin Core's own script interpreter";
        license = lib.licenses.mit;
        platforms = [
          "x86_64-linux"
          "aarch64-linux"
        ];
      };
    };

  # the runtime dependency set, as a function so the dev shell can reuse it
  # (uvicorn's [standard] extras are spelled out individually - nixpkgs
  # doesn't propagate extras)
  runtimeDeps =
    ps: with ps; [
      fastapi
      uvicorn
      httptools
      uvloop
      watchfiles
      websockets
      pyyaml
      python-dotenv
      bolt11
      httpx
      pydantic-settings
      qrcode
      bech32
      coincurve
      lnurlcashKernel
    ];

  # /docs' Swagger UI assets are deliberately not committed to the repo (no
  # static blobs in git) - fetched at build time instead, and a fetchurl
  # fixed-output derivation pins the sha256, so this works in the network-
  # less build sandbox and a CDN serving anything but those exact bytes
  # fails the build. Same files and hashes as scripts/fetch_swagger_ui.py
  # (used by the Dockerfile, CI, and the Makefile) - bump both together.
  swaggerUiVersion = "5.32.13";
  swaggerUiBundle = fetchurl {
    url = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@${swaggerUiVersion}/swagger-ui-bundle.js";
    hash = "sha256-Xzvl2c9AzdYNyg2v6vh0P9hY0bO7cXu9rr9yATA/Y9c=";
  };
  swaggerUiCss = fetchurl {
    url = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@${swaggerUiVersion}/swagger-ui.css";
    hash = "sha256-nmF9msCvsOQwwRoXNm3oYk23zjTJnr0pdEPwBIzjCJk=";
  };
in
python3Packages.buildPythonApplication rec {
  pname = "lnurl-mint";
  version = "0.1.5";
  pyproject = true;

  inherit src;

  # flake sources carry no .git for hatch-vcs to derive a version from
  env.SETUPTOOLS_SCM_PRETEND_VERSION = version;

  build-system = with python3Packages; [
    hatchling
    hatch-vcs
  ];

  dependencies = runtimeDeps python3Packages;

  # nixpkgs ships fastapi 0.139 where pyproject pins <0.116.0 - relax the
  # metadata bound and let the checkPhase's full test suite be the judge of
  # compatibility (if it ever breaks, the honest fix is bumping the pin
  # upstream, not hiding it here)
  pythonRelaxDeps = [ "fastapi" ];

  nativeBuildInputs = [ makeWrapper ];

  # the /docs assets (see the let block) are copied into the source tree
  # before the build: checkPhase runs pytest against the tree and the docs
  # tests serve them, and a flake source is a git tree, so gitignored files
  # are never in it
  postPatch = ''
    cp ${swaggerUiBundle} lnurl_mint/static/swagger-ui-bundle.js
    cp ${swaggerUiCss} lnurl_mint/static/swagger-ui.css
  '';

  # no [project.scripts] upstream - the app is served by uvicorn; wrap it so
  # `nix run` and the NixOS module have a single entry point to exec. The
  # wrapper captures the build-time PYTHONPATH (the full dependency closure)
  # plus this package's own site-packages.
  postInstall = ''
    makeWrapper ${lib.getExe python3Packages.uvicorn} $out/bin/lnurl-mint \
      --add-flags "lnurl_mint.server:app" \
      --prefix PYTHONPATH : "$out/${python3.sitePackages}:$PYTHONPATH"

    # hatchling excludes gitignored files from the wheel, so the /docs
    # assets copied into the tree above never reach site-packages - put them
    # there directly (the app resolves them relative to __file__)
    cp ${swaggerUiBundle} $out/${python3.sitePackages}/lnurl_mint/static/swagger-ui-bundle.js
    cp ${swaggerUiCss} $out/${python3.sitePackages}/lnurl_mint/static/swagger-ui.css
  '';

  nativeCheckInputs = [ python3Packages.pytest ];

  # conftest.py isolates itself (throwaway sqlite, dummy dotenv, testserver
  # BASE_URL, FakeNode) - the suite needs no network and no further setup.
  # `python -m pytest` rather than the bare console script: the test modules
  # do `from tests.conftest import ...`, which needs the repo root on
  # sys.path, which only the -m form adds
  checkPhase = ''
    runHook preCheck
    python -m pytest
    runHook postCheck
  '';

  passthru = {
    inherit bolt11 runtimeDeps;
  };

  meta = {
    description = "Minimal lnurlcash (LUD-25, Lightning bearer assets) mint - LUD-03/LUD-06 only";
    homepage = "https://github.com/dni/lnurl-mint";
    license = lib.licenses.mit;
    mainProgram = "lnurl-mint";
    platforms = lib.platforms.linux;
  };
}
