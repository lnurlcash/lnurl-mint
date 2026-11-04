{
  description = "Minimal lnurlcash (LUD-25, Lightning bearer assets) mint - LUD-03/LUD-06 only.";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        rec {
          lnurl-mint = pkgs.callPackage ./nix/package.nix {
            src = self;
            python3 = pkgs.python3;
          };
          default = lnurl-mint;
        }
      );

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.lnurl-mint}/bin/lnurl-mint";
        };
      });

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          python = pkgs.python3;
          runtimeDeps = self.packages.${system}.lnurl-mint.passthru.runtimeDeps;

          # nixpkgs ships black 26, whose new hugging style would reformat
          # the tree and fight CI - the project pins black 24 (see
          # pyproject), so the shell provides the pinned version, same
          # version+hash as uv.lock
          black = python.pkgs.buildPythonPackage rec {
            pname = "black";
            version = "24.10.0";
            pyproject = true;
            src = pkgs.fetchPypi {
              inherit pname version;
              hash = "sha256-hG6mTJev47xne3YXh5k75JkYEOzHpKk3gW3Wvd7cSHU=";
            };
            build-system = with python.pkgs; [
              hatchling
              hatch-fancy-pypi-readme
              hatch-vcs
            ];
            env.SETUPTOOLS_SCM_PRETEND_VERSION = version;
            dependencies = with python.pkgs; [
              click
              mypy-extensions
              packaging
              pathspec
              platformdirs
              tomli
            ];
            doCheck = false;
          };
        in
        {
          # python with the full runtime closure + test/lint tooling; pytest
          # runs against the working tree, so this replaces the fragile uv
          # venv entirely (coincurve comes prebuilt from nixpkgs)
          default = pkgs.mkShell {
            packages = [
              (python.withPackages (
                ps:
                runtimeDeps ps
                ++ [
                  ps.pytest
                  ps.mypy
                ]
              ))
              black
              pkgs.ruff
            ];
          };
        }
      );

      nixosModules = {
        lnurl-mint = import ./nix/module.nix { inherit self; };
        default = self.nixosModules.lnurl-mint;
      };

      checks = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          # the package build itself runs the full pytest suite (see
          # package.nix's checkPhase)
          inherit (self.packages.${system}) lnurl-mint;

          # nixpkgs certifi uses cacert rather than its bundled roots. Test
          # the actual trust store before relaxing its PyPI version bound.
          certifi-trust =
            pkgs.runCommand "lnurl-mint-certifi-trust"
              {
                nativeBuildInputs = [ (pkgs.python3.withPackages (ps: [ ps.certifi ])) ];
              }
              ''
                python ${./nix/check-certifi.py}
                touch $out
              '';

          # cheap evaluation check: the module merges and produces a sane
          # unit without building a whole NixOS system
          module-eval =
            let
              eval = nixpkgs.lib.nixosSystem {
                inherit system;
                modules = [
                  self.nixosModules.lnurl-mint
                  {
                    services.lnurl-mint = {
                      enable = true;
                      verifyEnabled = false;
                      fundingSource = {
                        backend = "cln";
                        url = "https://localhost:3010";
                      };
                      settings = {
                        BASE_URL = "https://mint.example";
                        BASE_FEE_MSAT = 1000;
                        # a raw key losing to its dedicated option is the
                        # documented precedence - pin it
                        VERIFY_ENABLED = true;
                      };
                    };
                    system.stateVersion = "25.11";
                  }
                ];
              };
            in
            pkgs.runCommand "lnurl-mint-module-eval" { } ''
              unit=${pkgs.writeText "unit.json" (builtins.toJSON {
                inherit (eval.config.systemd.services.lnurl-mint) serviceConfig environment;
              })}
              grep -q '"StateDirectory":"lnurl-mint"' $unit
              grep -q '"DynamicUser":true' $unit
              grep -q '"BASE_URL":"https://mint.example"' $unit
              grep -q '"VERIFY_ENABLED":"false"' $unit
              grep -q '"FUNDINGSOURCE_BACKEND":"cln"' $unit
              grep -q '"FUNDINGSOURCE_URL":"https://localhost:3010"' $unit
              grep -q '/bin/lnurl-mint --host 127.0.0.1 --port 8111' $unit
              touch $out
            '';

          # the real proof: a VM booting the module end-to-end
          vm-smoke = pkgs.testers.nixosTest {
            name = "lnurl-mint";
            nodes.machine =
              { ... }:
              {
                imports = [ self.nixosModules.lnurl-mint ];
                services.lnurl-mint = {
                  enable = true;
                  settings.BASE_URL = "http://localhost:8111";
                };
              };
            testScript = ''
              machine.wait_for_unit("lnurl-mint.service")
              machine.wait_for_open_port(8111)
              # LUD-06 payRequest works without a funding source configured
              # (no bare /p since #14 - the well-known alias is the only
              # payRequest entry point; `_` is the reserved bare-domain name)
              # (grep without -q: -q exits on first match and closes the
              # pipe, curl dies with SIGPIPE (exit 23), and the driver's
              # pipefail turns a PASSING match into a flaky failure)
              machine.succeed("curl -sf http://localhost:8111/.well-known/lnurlp/_ | grep withdrawLink")
              # the mutating callback correctly reports the missing funding source
              # (comment is LUD-25's mandatory comment protection - see
              # router.get_pay_callback - a well-formed one is required here to
              # get past that check and reach the funding-source check this pins)
              machine.succeed("curl -sf 'http://localhost:8111/p/cb?amount=50000&comment=0000000000000000000000000000000000000000000000000000000000000000' | grep 'not configured'")
              # the frontend one-pager renders
              machine.succeed("curl -sf http://localhost:8111/ | grep lnurl-mint")
            '';
          };
        }
      );
    };
}
