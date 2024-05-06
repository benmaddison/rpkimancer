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
          in
          with python3.pkgs; buildPythonPackage rec {
            pname = "rpkimancer";
            version = "0.2.3.dev1";
            src = ./.;
            format = "pyproject";
            nativeBuildInputs = [ setuptools-scm ];
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
            SETUPTOOLS_SCM_PRETEND_VERSION = version;
          };

        checks = { inherit (packages) default; };
      });
}
