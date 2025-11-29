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
    ntfs3g
  ];
  languages = {
    python = {
      enable = true;
      version = "3.13";
      # venv.enable = true;
      # venv.requirements = ''
      #   ${builtins.readFile (./requirements.txt)}
      # '';
      uv.enable = true;
      uv.sync.enable = true;
      uv.sync.allExtras = true;
      uv.sync.allGroups = true;
    };
  };
}
