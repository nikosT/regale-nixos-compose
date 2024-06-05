{ pkgs, modulesPath, nur, helpers, flavour, ... }: 
let
  compute_nodes = 8;

in {
  dockerPorts.frontend = [ "8443:443" "8000:80" ];
  dockerPorts.server = [ "5050:5050" ];
  nodes =
    let
      nodes_number = compute_nodes;
      nfsConfigs = import ./nfs.nix { inherit flavour; };
      commonConfig = import ./common_config.nix { inherit pkgs modulesPath nur flavour; };
      node = { ... }: {
        imports = [ commonConfig nfsConfigs.client ];
        services.oar.node = { enable = true; };
      };
    in
    {
      frontend = { ... }: {
        imports = [ commonConfig nfsConfigs.client ];
        # services.phpfpm.phpPackage = pkgs.php74;
        services.oar.client.enable = true;
        services.oar.web.enable = true;
        services.oar.web.drawgantt.enable = true;
        services.oar.web.monika.enable = true;

      };
      server = { ... }: {
        imports = [ commonConfig nfsConfigs.server ];
        services.oar.server.enable = true;
        services.oar.dbserver.enable = true;
        services.pgadmin = {
            enable = true;
            port = 5050;
            initialEmail = "test@oar.gr";
            initialPasswordFile = pkgs.writeText "pgadmin4-password.txt" "testoar";
            settings = {
                DEFAULT_SERVER = "0.0.0.0";
            };
        };
      };
    } // helpers.makeMany node "node" nodes_number;
    rolesDistribution = { nodes = compute_nodes; };

  testScript = ''
    frontend.succeed("true")
    # Prepare a simple script which execute cg.C.mpi
    frontend.succeed('echo "mpirun --hostfile \$OAR_NODEFILE -mca pls_rsh_agent oarsh -mca btl tcp,self cg.C.mpi" > /users/user1/test.sh')
    # Set rigth and owner of script
    frontend.succeed("chmod 755 /users/user1/test.sh && chown user1 /users/user1/test.sh")
    # Submit job with script under user1
    frontend.succeed('su - user1 -c "cd && oarsub -l nodes=2 ./test.sh"')
    # Wait output job file
    frontend.wait_for_file('/users/user1/OAR.1.stdout')
    # Check job's final state
    frontend.succeed("oarstat -j 1 -s | grep Terminated")
  '';
}
