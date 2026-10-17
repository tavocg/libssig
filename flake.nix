{
  description = "libssig: simple signing";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            name = "libssig";

            packages = with pkgs; [
              gcc
              clang-tools
              cmake
              opensc
              pcsc-tools
            ];

            nativeBuildInputs = with pkgs; [
              pkg-config
            ];

            buildInputs = with pkgs; [
              p11-kit
              openssl
            ];

            shellHook = ''
              export PKCS11_MODULE="${pkgs.opensc}/lib/opensc-pkcs11.so"

              if [[ $- == *i* ]]; then
                PS1="(libssig) $PS1"
              fi
            '';
          };
        });
    };
}
