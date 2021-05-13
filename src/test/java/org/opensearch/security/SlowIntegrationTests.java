/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package org.opensearch.security;

import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.common.settings.Settings;
import org.opensearch.node.Node;
import org.opensearch.node.PluginAwareNode;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.cluster.ClusterConfiguration;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.transport.Netty4Plugin;
import org.junit.Assert;
import org.junit.Test;

public class SlowIntegrationTests extends SingleClusterTest {

    @Test
    public void testCustomInterclusterRequestEvaluator() throws Exception {
        
        final Settings settings = Settings.builder()
                .put(ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS, "org.opensearch.security.AlwaysFalseInterClusterRequestEvaluator")
                .put("discovery.initial_state_timeout","8s")
                .build();
        setup(Settings.EMPTY, null, settings, false, ClusterConfiguration.DEFAULT ,5,1);
        Assert.assertEquals(1, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
    }

    @SuppressWarnings("resource")
    @Test
    public void testNodeClientAllowedWithServerCertificate() throws Exception {
        setup();
        Assert.assertEquals(clusterInfo.numNodes, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
    
        
        final Settings tcSettings = Settings.builder()
                .put(minimumSecuritySettings(Settings.EMPTY).get(0))
                .put("cluster.name", clusterInfo.clustername)
                .put("node.data", false)
                .put("node.master", false)
                .put("node.ingest", false)
                .put("path.data", "./target/data/" + clusterInfo.clustername + "/cert/data")
                .put("path.logs", "./target/data/" + clusterInfo.clustername + "/cert/logs")
                .put("path.home", "./target")
                .put("node.name", "transportclient")
                .put("discovery.initial_state_timeout","8s")
                .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost+":"+clusterInfo.nodePort)
                .build();
    
        log.debug("Start node client");
        
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class, OpenDistroSecurityPlugin.class).start()) {
            Assert.assertFalse(node.client().admin().cluster().health(new ClusterHealthRequest().waitForNodes(String.valueOf(clusterInfo.numNodes+1))).actionGet().isTimedOut());
            Assert.assertEquals(clusterInfo.numNodes+1, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());    
        }
    }
    
    @SuppressWarnings("resource")
    @Test
    public void testNodeClientDisallowedWithNonServerCertificate() throws Exception {
        setup();
        Assert.assertEquals(clusterInfo.numNodes, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
    
        
        final Settings tcSettings = Settings.builder()
                .put(minimumSecuritySettings(Settings.EMPTY).get(0))
                .put("cluster.name", clusterInfo.clustername)
                .put("node.data", false)
                .put("node.master", false)
                .put("node.ingest", false)
                .put("path.data", "./target/data/" + clusterInfo.clustername + "/cert/data")
                .put("path.logs", "./target/data/" + clusterInfo.clustername + "/cert/logs")
                .put("path.home", "./target")
                .put("node.name", "transportclient")
                .put("discovery.initial_state_timeout","8s")
                .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost+":"+clusterInfo.nodePort)
                .put("opendistro_security.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("kirk-keystore.jks"))
                .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS,"kirk")
                .build();
    
        log.debug("Start node client");

        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class, OpenDistroSecurityPlugin.class).start()) {
            Thread.sleep(10000);
            Assert.assertEquals(1, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());    
        } catch (Exception e) {
            Assert.fail(e.toString());
        }
         
    }
    
    @SuppressWarnings("resource")
    @Test
    public void testNodeClientDisallowedWithNonServerCertificate2() throws Exception {
        setup();
        Assert.assertEquals(clusterInfo.numNodes, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());
     
        final Settings tcSettings = Settings.builder()
                .put(minimumSecuritySettings(Settings.EMPTY).get(0))
                .put("cluster.name", clusterInfo.clustername)
                .put("node.data", false)
                .put("node.master", false)
                .put("node.ingest", false)
                .put("path.data", "./target/data/" + clusterInfo.clustername + "/cert/data")
                .put("path.logs", "./target/data/" + clusterInfo.clustername + "/cert/logs")
                .put("path.home", "./target")
                .put("node.name", "transportclient")
                .put("discovery.initial_state_timeout","8s")
                .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost+":"+clusterInfo.nodePort)
                .put("opendistro_security.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("spock-keystore.jks"))
                .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS,"spock")
                .build();
    
        log.debug("Start node client");
        
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class, OpenDistroSecurityPlugin.class).start()) {
            Thread.sleep(10000);
            Assert.assertEquals(1, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());    
        } catch (Exception e) {
            Assert.fail(e.toString());
        }
    }

}
