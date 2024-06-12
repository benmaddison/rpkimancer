{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, ... } @ inputs:
    inputs.flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import inputs.nixpkgs { inherit system; };
      in
      rec {
        packages.default =
          let
            python3 = pkgs.python3.override {
              packageOverrides = self: super: {
                pycrate = super.buildPythonPackage rec {
                  pname = "pycrate";
                  version = "0.5.5";
                  src = super.fetchPypi {
                    inherit pname version;
                    hash = "sha256-WfCTMYkKOJprmEEvGfT7AhxadaNasHv1ug0eKZoJZ68=";
                  };
                  doCheck = false;
                };
              };
            };
            editableInstallShellHook =
              let
                inherit (python3) interpreter sitePackages;
                inherit (python3.pkgs) pip;
              in
              pkgs.makeSetupHook
                {
                  name = "editable-install-hook";
                  propagatedBuildInputs = [ pip ];
                }
                (pkgs.writeShellScript "editable-install-hook.sh" /* bash */ ''
                  editableInstallShellHook() {
                    echo "Executing editableInstallShellHook"
                    runHook preShellHook

                    tmp_path="$(mktemp -d)"
                    export PATH="$tmp_path/bin:$PATH"
                    export PYTHONPATH="$tmp_path/${sitePackages}:$PYTHONPATH"
                    mkdir -p "$tmp_path/${sitePackages}"
                    ${interpreter} -m pip install -e . --prefix "$tmp_path" --no-deps --no-build-isolation
                    export NIX_PYTHONPATH="$tmp_path/${sitePackages}:''${NIX_PYTHONPATH-}"

                    runHook postShellHook
                    echo "Finished executing editableInstallShellHook"
                  }
                  if [ -z "''${shellHook-}" ]; then
                    echo "Using editableInstallShellHook"
                    shellHook=editableInstallShellHook
                  fi
                '');
          in
          with python3.pkgs; buildPythonPackage rec {
            pname = "rpkimancer";
            version = "0.2.3.dev1";
            src = ./.;
            format = "pyproject";
            nativeBuildInputs = [
              setuptools-scm
              editableInstallShellHook
            ];
            propagatedBuildInputs = [
              argcomplete
              cryptography
              pycrate
            ];
            nativeCheckInputs = [
              pytestCheckHook
            ];
            pytestFlagsArray = [
              "-m 'not rpki_client'"
              "-ra"
              "-vs"
              "--strict-markers"
            ];
            postShellHook = /* bash */ ''
              eval "$(${argcomplete}/bin/register-python-argcomplete rpkincant)"
            '';
            SETUPTOOLS_SCM_PRETEND_VERSION = version;
          };

        checks = { inherit (packages) default; };
      });
}
