{
  description = "fishnet: run apps through a VPN inside a network namespace";

  inputs.nixpkgs.url = "https://channels.nixos.org/nixpkgs-unstable/nixexprs.tar.zst";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      cargoToml = fromTOML (builtins.readFile ./Cargo.toml);

      # Same native deps as the dev shell, so both build the same way.
      bindgenEnv = {
        LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
        BINDGEN_EXTRA_CLANG_ARGS = "-I${pkgs.linuxHeaders}/include";
      };
    in
    {
      packages.${system} = rec {
        fishnet = pkgs.rustPlatform.buildRustPackage {
          pname = "fishnet";
          version = cargoToml.package.version;
          src = self;
          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.libnftnl pkgs.libmnl ];
          env = bindgenEnv;

          doCheck = false; # tests would need root and real namespaces

          meta = {
            description = "Run apps through a VPN inside a network namespace";
            mainProgram = "fishnet";
            platforms = pkgs.lib.platforms.linux;
          };
        };
        default = fishnet;
      };

      nixosModules.default = { config, lib, pkgs, ... }:
        let cfg = config.programs.fishnet; in
        {
          options.programs.fishnet = {
            enable = lib.mkEnableOption "fishnet";
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              description = "The fishnet package to install.";
            };
            sudoGroup = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = ''
                Group whose members may run `fishnet up/down/status/ps/exec` via sudo without a
                password. `connect` always needs a password.
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            environment.systemPackages = [ cfg.package ];

            users.groups = lib.mkIf (cfg.sudoGroup != null) { ${cfg.sudoGroup} = { }; };
            security.sudo.extraRules = lib.mkIf (cfg.sudoGroup != null) [{
              groups = [ cfg.sudoGroup ];
              commands = map
                (c: { command = "/run/current-system/sw/bin/fishnet ${c}"; options = [ "NOPASSWD" ]; })
                [ "up" "down" "status" "ps" "ps *" "exec *" ];
            }];
          };
        };

      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          cargo
          rustc
          pkg-config
          libclang
          libnftnl
          libmnl
          linuxHeaders
        ];
        env = bindgenEnv;
      };
    };
}
