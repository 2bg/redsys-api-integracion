package sis.redsys.api;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static junit.framework.Assert.assertTrue;

public class ApiMacSha256Test {

	@Test
	public void cuandoMultiplesHilosLlamanALaAPI_LosResultadosObtenidosPorUnThreadNoDebenSerIgualesALasDeOTroParaPedidosDiferentes() throws Exception {

		Callable<String> obtenedorDeParametros = new Callable<String>() {

			@Override
			public String call() throws Exception {
				String orderNumberImposibleQueSeaIgualAOtra = System.nanoTime() + new SecureRandom().nextLong() + "";
				ApiMacSha256.setParameter("DS_MERCHANT_ORDER", orderNumberImposibleQueSeaIgualAOtra);
				String merchantParametersCreated = ApiMacSha256.createMerchantParameters();
				System.out.println("order:"+orderNumberImposibleQueSeaIgualAOtra+"   result->"+merchantParametersCreated);
				return merchantParametersCreated;
			}

		};

		List<Future<String>> listaDeResultados = new ArrayList<Future<String>>();
		ExecutorService threadPool = Executors.newFixedThreadPool(2);
		for (int i = 0; i < 100; i++) {
			listaDeResultados.add(threadPool.submit(obtenedorDeParametros));

		}
		//Esperamos un poco a que todos los threads terminen
		Thread.sleep(5000);

		Set<String> detectorDeColisiones = new HashSet<String>();
		for (Future<String> res : listaDeResultados) {
			String parametrosPedido = res.get();
			assertTrue("El resultado esta duplicado :"+parametrosPedido,detectorDeColisiones.add(parametrosPedido));
		}

	}
}
