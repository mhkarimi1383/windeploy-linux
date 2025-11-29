{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:

{
  packages = with pkgs; [
    git
    wimlib
    parted
  ];
  languages = {
    python = {
      enable = true;
      version = "3.13";
      venv.enable = true;
      venv.requirements = ''
        ${builtins.readFile (./requirements.txt)}
      '';
    };
  };
}
