# This file is part of libssig.
# Copyright (C) 2026 Gustavo Calvo <tavo@tavo.cr>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# See libssig/libssig.c for the full copyright and warranty notice.
# See LICENSE in the project root for the GNU General Public License.

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
              file
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
