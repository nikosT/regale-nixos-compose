{ pkgs, modulesPath, nur, helpers, ... }: {
  roles =
    let
      commonConfig = import ./common_config.nix { inherit pkgs modulesPath nur; };
      tokenFile = pkgs.writeText "token" "p@s$w0rd";
    in
    {
      frontend = { ... }: {
        imports = [ commonConfig ];
        nxc.sharedDirs."/users".server = "server";

        services.oar.client.enable = true;
        services.oar.web.enable = true;
        services.oar.web.drawgantt.enable = true;
        services.oar.web.monika.enable = true;
      };
      server = { ... }: {
        imports = [ commonConfig ];
        nxc.sharedDirs."/users".export = true;

        services.oar.server.enable = true;
        services.oar.dbserver.enable = true;

        # K3s utils
        environment.systemPackages = with pkgs; [ gzip jq kubectl ];

        services.k3s = {
          inherit tokenFile;
          enable = true;
          role = "server";
          package = pkgs.k3s;
          # FIXME: WARNING: These IP adresses are static values that only work for VM flavor and 2 nodes
          extraFlags = "--bind-address 192.168.1.4 --node-external-ip 192.168.1.4";
        };
      };

      node = { ... }: {
        imports = [ commonConfig ];
        nxc.sharedDirs."/users".server = "server";

        services.oar.node.enable = true;

        services.k3s = {
          inherit tokenFile;
          enable = true;
          role = "agent";
          serverAddr = "https://server:6443";
        };
      };
    };

  rolesDistribution = { node = 2; };

  testScript = ''
    # Submit job with script under user1
    frontend.succeed('su - user1 -c "cd && oarsub -l nodes=2 \"hostname\""')

    # Wait output job file
    frontend.wait_for_file('/users/user1/OAR.1.stdout')

    # Check job's final state
    frontend.succeed("oarstat -j 1 -s | grep Terminated")
  '';
}
